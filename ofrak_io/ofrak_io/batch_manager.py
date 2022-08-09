import asyncio
from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Callable, Dict, Awaitable, Iterable, Tuple, ClassVar

Request = TypeVar("Request")
Result = TypeVar("Result")


_RequestKeyT = str
_BatchHandlerFunctionT = Callable[
    [Tuple[Request, ...]], Awaitable[Iterable[Tuple[Request, Result]]]
]
_DEFAULT_RATE_LIMIT = 10


def _DEFAULT_REQUEST_KEY(req):
    return str(hash(req))


class NotAllRequestsHandledError(Exception):
    pass


class BatchManagerInterface(Generic[Request, Result], ABC):
    """
    Class which manages automatically batching async requests to some resource (like a remote
    server) to limit the number of individual requests.
    """

    @abstractmethod
    async def get_result(self, request: Request) -> Result:
        """
        Get the result for a request. The request may be batched with one or more other pending
        requests before being passed to the `handler_function`.

        :param request: request to be passed in the argument of `handler_function`

        :return: result for the given request

        :raises NotAllRequestsHandledError: if this or any other requests were not handled by the
        `handler_function` passed to the constructor.
        """
        raise NotImplementedError()


def make_batch_manager(
    handler_function: _BatchHandlerFunctionT,
    rate_limit: int = _DEFAULT_RATE_LIMIT,
    request_key_f: Callable[[Request], _RequestKeyT] = _DEFAULT_REQUEST_KEY,
) -> BatchManagerInterface[Request, Result]:
    """
    Construct an object which will automatically batch every call to `get_result` into periodic
    calls to `handler_function`.

    This function is the preferred way to make a one-off batch manager with minimal lines of
    code. If you find yourself calling this function with the same arguments multiple times,
    consider instead defining a subclass of `AbstractBatchManager`. This is functionally
    equivalent to calling `make_batch_manager` with the same arguments, but the code is cleaner.

    The returned BatchManagerInterface is implemented for asyncio, but is NOT GENERALLY
    THREAD-SAFE! That is, it must not be shared between manually accessed threads.

    :param handler_function: function to handle multiple requests at once and return the results
    as pairs of (request, result)
    :param rate_limit:  maximum number of times `handler_function` will be called per second
    :param request_key_f: function this manager should use to uniquely identify requests

    :return: an instance of a `BatchManagerInterface` using `handler_function` to get results
    """
    return _BatchManagerImplementation(handler_function, rate_limit, request_key_f)


class _BatchManagerImplementation(BatchManagerInterface[Request, Result]):
    def __init__(
        self,
        handler_function: _BatchHandlerFunctionT,
        rate_limit: int,
        request_key_f: Callable[[Request], _RequestKeyT],
    ):
        # Basic state setup
        self._request_key_f = request_key_f
        self._handler_function = handler_function
        self._rate_limit = rate_limit
        # Background task and batch setup
        loop = asyncio.get_event_loop()
        self._handler_loop_task = loop.create_task(self._periodic_batch_handler())
        self._current_batch = self._new_batch()

    async def get_result(self, request: Request) -> Result:
        current_batch = self._current_batch
        current_batch.add_request(request)
        # Gives self._handler_loop_task a chance to raise its errors
        done, _ = await asyncio.wait(
            (current_batch.result(request), self._handler_loop_task),
            return_when=asyncio.FIRST_COMPLETED,
        )
        return next(iter(done)).result()

    async def _periodic_batch_handler(self):
        while True:
            await asyncio.sleep(1.0 / float(self._rate_limit))
            old_batch = self._current_batch
            if old_batch.has_requests():
                self._current_batch = self._new_batch()
                handled_results = await self._handler_function(old_batch.get_requests())
                old_batch.resolve_batch_requests(handled_results)

    def _new_batch(self):
        return _Batch[Request, Result](self._request_key_f)


class AbstractBatchManager(_BatchManagerImplementation[Request, Result], ABC):
    """
    An implementation of `BatchManagerInterface` which allows for defining a pattern of
    batch managers as a subclass. See that `BatchManagerInterface`'s documentation for details on
    what this class does. This class is a Generic type with two type arguments, for the type of
    each individual request and each individual return type.

    Subclassing AbstractBatchManager is preferred when `make_batch_manager` is called in multiple
    places with the same arguments, or if the handler function needs some persistent state. For
    making a one-off batch manager with minimal lines of code, use `make_batch_manager`.

    This class is implemented for asyncio, but is NOT GENERALLY THREAD-SAFE! That is, instances
    must not be shared between manually accessed threads.

    :cvar rate_limit: maximum number of times `handle_requests` will be called per second
    (equivalent to `rate_limit` argument to `make_batch_manager`)
    """

    rate_limit: ClassVar[int] = _DEFAULT_RATE_LIMIT

    def __init__(self):
        super().__init__(self.handle_requests, self.rate_limit, self.unique_key_for_request)

    @abstractmethod
    async def handle_requests(
        self, requests: Tuple[Request, ...]
    ) -> Iterable[Tuple[Request, Result]]:
        """
        Handle multiple requests at once and return the results as pairs of (request, result).
        Equivalent to `handler_function` argument to `make_batch_manager`.

        :param requests: one or more objects that were passed to `get_result`

        :return: pairs of (request, result)
        """
        raise NotImplementedError()

    @staticmethod
    def unique_key_for_request(request: Request) -> _RequestKeyT:
        """
        Function to uniquely identify requests. If the Request type is unhashable, this method
        must be overridden (the default function uses the hash).

        Equivalent to `request_key_f` argument to `make_batch_manager`.
        """
        return _DEFAULT_REQUEST_KEY(request)


class _Batch(Generic[Request, Result]):
    def __init__(self, request_key):
        self._request_key = request_key
        self._batch_was_handled = asyncio.Event()
        self._unresolved_requests: Dict[_RequestKeyT, Request] = dict()
        self._resolved_requests: Dict[_RequestKeyT, Result] = dict()

    def add_request(self, request: Request):
        self._unresolved_requests[self._request_key(request)] = request

    def has_requests(self) -> bool:
        return not len(self._unresolved_requests) == 0

    def get_requests(self) -> Tuple[Request, ...]:
        return tuple(self._unresolved_requests.values())

    async def result(self, request: Request) -> Result:
        await self._batch_was_handled.wait()
        return self._resolved_requests[self._request_key(request)]

    def resolve_batch_requests(self, request_result_pairs: Iterable[Tuple[Request, Result]]):
        for req, res in request_result_pairs:
            k = self._request_key(req)
            self._resolved_requests[k] = res
            self._unresolved_requests.pop(k)

        if len(self._unresolved_requests) != 0:
            raise NotAllRequestsHandledError(
                f"Could not get the results for this batch because "
                f"{len(self._unresolved_requests)} requests were unhandled!"
            )
        self._batch_was_handled.set()
