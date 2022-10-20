import asyncio
import functools
import json
import logging
import sys
from typing import (
    Iterable,
    Optional,
    Dict,
    cast,
    Set,
    Tuple,
    no_type_check,
    Union,
    Type,
    Callable,
    TypeVar,
    List,
)

from aiohttp import web, ClientResponse
from aiohttp.web_exceptions import HTTPBadRequest
from aiohttp.web_request import Request
from aiohttp.web_response import Response
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

from ofrak import (
    OFRAKContext,
    OFRAK,
    ResourceFilter,
    ResourceAttributeRangeFilter,
    ResourceAttributeValueFilter,
    ResourceSort,
)
from ofrak.core import File, Addressable
from ofrak.core import (
    GenericBinary,
    AddCommentModifier,
    AddCommentModifierConfig,
    DeleteCommentModifierConfig,
    DeleteCommentModifier,
    StringFindReplaceConfig,
    StringFindReplaceModifier,
)
from ofrak.model.component_model import (
    ComponentContext,
    ClientComponentContext,
    ComponentRunResult,
)
from ofrak.model.resource_model import (
    ResourceContext,
    ClientResourceContext,
    ResourceModel,
)
from ofrak.model.viewable_tag_model import ResourceViewContext
from ofrak.resource import Resource
from ofrak.service.error import SerializedError
from ofrak.service.serialization.pjson import (
    SerializationServiceInterface,
    PJSONSerializationService,
)
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak_components.entropy import DataSummaryAnalyzer

T = TypeVar("T")
LOGGER = logging.getLogger(__name__)


def exceptions_to_http(error_class: Type[SerializedError]):
    """
    Decorator for a server function that attempts to do some work, and
    forwards the exception, if any, to the client over HTTP.

    Usage:

    @exceptions_to_http(MyErrorClass)
    async def handle_some_request(self, request...):
        ...
    """

    def exceptions_to_http_decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as error:
                LOGGER.exception("Exception raised in aiohttp endpoint")
                return respond_with_error(error, error_class)

        return wrapper

    return exceptions_to_http_decorator


class AiohttpOFRAKServer:
    routes = web.RouteTableDef()

    def __init__(
        self,
        serializer: SerializationServiceInterface,
        ofrak_context: OFRAKContext,
        host: str,
        port: int,
    ):
        self._serializer = serializer
        self._app = web.Application(client_max_size=None)  # type: ignore
        self._host = host
        self._port = port
        self._ofrak_context = ofrak_context
        self.resource_context: ResourceContext = ClientResourceContext()
        self.resource_view_context: ResourceViewContext = ResourceViewContext()
        self.component_context: ComponentContext = ClientComponentContext()

        self._app.add_routes(
            [
                web.post("/create_root_resource", self.create_root_resource),
                web.get("/get_root_resources", self.get_root_resources),
                web.get("/{resource_id}/", self.get_resource),
                web.get("/{resource_id}/get_data", self.get_data),
                web.get(
                    "/{resource_id}/get_data_range_within_parent",
                    self.get_data_range_within_parent,
                ),
                web.get("/{resource_id}/get_root", self.get_root_resource_from_child),
                web.post("/{resource_id}/unpack", self.unpack),
                web.post("/{resource_id}/unpack_recursively", self.unpack_recursively),
                web.post("/{resource_id}/pack", self.pack),
                web.post("/{resource_id}/pack_recursively", self.pack_recursively),
                web.post("/{resource_id}/analyze", self.analyze),
                web.post("/{resource_id}/identify", self.identify),
                web.post("/{resource_id}/data_summary", self.data_summary),
                web.get("/{resource_id}/get_parent", self.get_parent),
                web.get("/{resource_id}/get_ancestors", self.get_ancestors),
                web.get("/{resource_id}/get_children", self.get_children),
                web.post("/{resource_id}/queue_patch", self.queue_patch),
                web.post("/{resource_id}/create_mapped_child", self.create_mapped_child),
                web.post("/{resource_id}/find_and_replace", self.find_and_replace),
                web.post("/{resource_id}/add_comment", self.add_comment),
                web.post("/{resource_id}/delete_comment", self.delete_comment),
                web.post("/{resource_id}/search_for_vaddr", self.search_for_vaddr),
            ]
        )

        self._job_ids: Dict[str, bytes] = dict()

    def run(self):
        """
        Start and run the server until shutdown is requested via e.g. SIGINT.
        """
        web.run_app(self._app, host=self._host, port=self._port)

    async def start(self):
        """
        Start the server then return.
        """
        self.runner = web.AppRunner(self._app)
        await self.runner.setup()
        server = web.TCPSite(self.runner, host=self._host, port=self._port)
        await server.start()

    async def run_until_cancelled(self):
        """
        To be run after `start_server`, within an asyncio Task.
        cancel() that task to shutdown the server.
        """
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.runner.cleanup()

    @exceptions_to_http(SerializedError)
    async def create_root_resource(self, request: Request) -> Response:
        name = request.query.get("name")
        if name is None:
            return HTTPBadRequest(reason="Missing root resource `name` from request")
        resource_data = await request.read()
        root_resource = await self._ofrak_context.create_root_resource(name, resource_data, (File,))
        if request.remote is not None:
            self._job_ids[request.remote] = root_resource.get_job_id()
        return web.json_response(self._serialize_resource(root_resource))

    @exceptions_to_http(SerializedError)
    async def get_root_resources(self, request: Request) -> Response:
        roots = await self._ofrak_context.resource_service.get_root_resources()
        return web.json_response(list(map(self._serialize_resource_model, roots)))

    @exceptions_to_http(SerializedError)
    async def get_resource(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        return web.json_response(self._serialize_resource(resource))

    @exceptions_to_http(SerializedError)
    async def get_data(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        _range = self._serializer.from_pjson(
            get_query_string_as_pjson(request).get("range"), Optional[Range]
        )
        data = await resource.get_data(_range)
        return Response(body=data)

    @exceptions_to_http(SerializedError)
    async def get_data_range_within_parent(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        data_range = await resource.get_data_range_within_parent()
        return Response(
            content_type="application/json",
            body=self._serializer.to_json(data_range, Range),
        )

    @exceptions_to_http(SerializedError)
    async def unpack(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        result = await resource.unpack()
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    @exceptions_to_http(SerializedError)
    async def unpack_recursively(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        result = await resource.unpack_recursively()
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    @exceptions_to_http(SerializedError)
    async def pack(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        result = await resource.pack()
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    @exceptions_to_http(SerializedError)
    async def pack_recursively(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        result = await resource.pack_recursively()
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    @exceptions_to_http(SerializedError)
    async def identify(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        result = await resource.auto_run(all_identifiers=True)
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    @exceptions_to_http(SerializedError)
    async def data_summary(self, request: Request) -> Response:
        resource = cast(Resource, await self._get_resource_for_request(request))
        result = await resource.run(DataSummaryAnalyzer)
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    @exceptions_to_http(SerializedError)
    async def analyze(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        result = await resource.auto_run(all_analyzers=True)
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    @exceptions_to_http(SerializedError)
    async def get_parent(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        parent = await resource.get_parent()
        return web.json_response(self._serialize_resource(parent))

    @exceptions_to_http(SerializedError)
    async def get_ancestors(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        # TODO: filter argument
        ancestors = await resource.get_ancestors()
        return web.json_response(self._serialize_multi_resource(ancestors))

    @exceptions_to_http(SerializedError)
    async def get_children(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        children = await resource.get_children()
        return web.json_response(self._serialize_multi_resource(children))

    @exceptions_to_http(SerializedError)
    async def get_root_resource_from_child(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        parent = resource
        try:
            # Assume get_ancestors returns an ordered list with the parent first and the root last
            for parent in await resource.get_ancestors():
                pass
        except NotFoundError:
            pass
        return web.json_response(self._serialize_resource(parent))

    @exceptions_to_http(SerializedError)
    async def queue_patch(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        new_data = await request.read()

        start_param = request.query.get("start")
        start = int(start_param) if start_param is not None else 0
        end_param = request.query.get("end")
        end = int(end_param) if end_param is not None else (await resource.get_data_length())

        resource.queue_patch(Range(start, end), new_data)
        await resource.save()
        return web.json_response(self._serialize_resource(resource))

    @exceptions_to_http(SerializedError)
    async def create_mapped_child(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        _range = self._serializer.from_pjson(await request.json(), Optional[Range])
        child = await resource.create_child(tags=(GenericBinary,), data_range=_range)
        return web.json_response(self._serialize_resource(child))

    @exceptions_to_http(SerializedError)
    async def find_and_replace(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        config = self._serializer.from_pjson(await request.json(), StringFindReplaceConfig)
        result = await resource.run(StringFindReplaceModifier, config=config)
        response_pjson = await self._serialize_component_result(result)
        return web.json_response(response_pjson)

    async def add_comment(self, request: Request) -> Response:
        """
        Expected POST body is a comment in the form Tuple[Optional[Range], str] (serialized to JSON).
        """
        resource = await self._get_resource_for_request(request)
        comment = self._serializer.from_pjson(await request.json(), Tuple[Optional[Range], str])
        result = await resource.run(AddCommentModifier, AddCommentModifierConfig(comment))
        return web.json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def delete_comment(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        comment_range = self._serializer.from_pjson(await request.json(), Optional[Range])
        result = await resource.run(
            DeleteCommentModifier, DeleteCommentModifierConfig(comment_range)
        )
        return web.json_response(await self._serialize_component_result(result))

    @exceptions_to_http(SerializedError)
    async def search_for_vaddr(self, request: Request) -> Response:
        resource = await self._get_resource_for_request(request)
        vaddr_start, vaddr_end = self._serializer.from_pjson(
            await request.json(), Tuple[int, Optional[int]]
        )
        try:
            if vaddr_end is not None:
                vaddr_filter = ResourceAttributeRangeFilter(
                    Addressable.VirtualAddress, vaddr_start, vaddr_end
                )
            else:
                vaddr_filter = ResourceAttributeValueFilter(Addressable.VirtualAddress, vaddr_start)
            matching_resources = await resource.get_descendants(
                r_filter=ResourceFilter(attribute_filters=(vaddr_filter,)),
                r_sort=ResourceSort(Addressable.VirtualAddress),
            )
            return web.json_response(list(map(self._serialize_resource, matching_resources)))

        except NotFoundError:
            return web.json_response([])

    async def _get_resource_by_id(self, resource_id: bytes, job_id: bytes) -> Resource:
        resource = await self._ofrak_context.resource_factory.create(
            job_id,
            resource_id,
            self.resource_context,
            self.resource_view_context,
            self.component_context,
        )
        return resource

    async def _serialize_component_result(self, result: ComponentRunResult) -> PJSONType:
        async def get_and_serialize(resource_id) -> PJSONType:
            resource_model = await self._ofrak_context.resource_service.get_by_id(resource_id)
            return self._serialize_resource_model(resource_model)

        serialized_result = {
            "created": await asyncio.gather(*map(get_and_serialize, result.resources_created)),
            "modified": await asyncio.gather(
                *map(
                    get_and_serialize,
                    result.resources_modified.difference(result.resources_created),
                )
            ),
            "deleted": self._serializer.to_pjson(result.resources_deleted, Set[bytes]),
        }
        return serialized_result

    async def _get_resource_for_request(self, request: Request) -> Resource:
        resource_id = pluck_id(request, "resource_id")
        if request.remote is not None:
            job_id = self._job_ids[request.remote]
        else:
            raise ValueError("No IP address found for the remote request!")
        return await self._get_resource_by_id(resource_id, job_id)

    def _serialize_resource_model(self, resource_model: ResourceModel) -> PJSONType:
        """
        Serialize the resource model, stripped of information irrelevant to the frontend.
        """
        resource_model_pjson = self._serializer.to_pjson(resource_model, ResourceModel)
        self._strip_resource_model_pjson(resource_model_pjson)
        return resource_model_pjson

    def _serialize_resource(self, resource: Resource) -> PJSONType:
        """
        Serialize the resource as a serialized model, stripped of information irrelevant to the
        frontend.
        """
        return self._serialize_resource_model(resource.get_model())

    def _serialize_multi_resource(self, resources: Iterable[Resource]) -> PJSONType:
        """
        Serialize the resources as serialized models, stripped of information irrelevant to the
        frontend.
        """
        return list(map(self._serialize_resource, resources))

    def _strip_resource_model_pjson(self, resource_model_pjson: PJSONType):
        resource_model_fields: Dict = cast(Dict, resource_model_pjson)
        del resource_model_fields["data_dependencies"]
        del resource_model_fields["attribute_dependencies"]
        del resource_model_fields["component_versions"]
        del resource_model_fields["components_by_attributes"]

    async def message_as_pjson(
        self, message: Union[Request, ClientResponse]
    ) -> Dict[str, PJSONType]:
        """
        Read the HTTP message (request or response) and return it in PJSON form.

        It's assumed that the message is a dictionary.
        """
        message_raw = await message.read()
        return json.loads(message_raw.decode("UTF-8"))

    # ignore type hints because mypy doesn't currently allow to use Type[X] when X is not a concrete type,
    # see e.g. https://github.com/python/mypy/issues/4717#issuecomment-617676034
    @no_type_check
    async def deserialize_message(
        self, message: Union[Request, ClientResponse], type_hint: Type[T]
    ) -> T:
        """
        Read the HTTP message (request or response) and return it in deserialized form.

        Convenience function for when a type hint is all that's needed to deserialize the message.
        """
        return self._serializer.from_pjson(await self.message_as_pjson(message), type_hint)


async def main(ofrak_context: OFRAKContext, host: str, port: int):
    # Force using the correct PJSON serialization with the expected structure. Otherwise the
    # dependency injector may accidentally use the Stashed PJSON serialization service,
    # which returns PJSON that has a different, problematic structure.
    ofrak_context.injector.bind_factory(PJSONSerializationService)

    ofrak_context.injector.bind_factory(
        AiohttpOFRAKServer,
        ofrak_context=ofrak_context,
        host=host,
        port=port,
    )
    server = await ofrak_context.injector.get_instance(AiohttpOFRAKServer)
    await server.start()

    print("Started server")

    await server.run_until_cancelled()


def respond_with_error(error: Exception, error_cls: Type[SerializedError]) -> Response:
    if isinstance(error, error_cls):
        text = error.to_json()
    else:
        text = json.dumps(error_cls.to_dict(error))
    response = Response(text=text, status=500)
    return response


def pluck_id(request: Request, get_parameter_name: str) -> bytes:
    return bytes.fromhex(request.match_info[get_parameter_name])


def pluck_ids(request: Request, get_parameter_name: str) -> List[bytes]:
    ids_hex = request.match_info[get_parameter_name].split(",")
    return [bytes.fromhex(id) for id in ids_hex]


def get_query_string_as_pjson(request: Request) -> Dict[str, PJSONType]:
    """
    URL-encoded GET parameters are all strings. For example, None is encoded as 'None',
    or 1 as '1', which isn't valid PJSON. We fix this by applying `json.loads` on each parameter.
    """
    return {key: json.loads(value) for key, value in request.query.items()}


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        _host = sys.argv[1]
        _port = int(sys.argv[2])
    else:
        _host = "127.0.0.1"
        _port = 8080

    if len(sys.argv) == 4:
        backend = sys.argv[3]
    else:
        backend = None

    ofrak = OFRAK(logging.INFO)

    if backend == "binary-ninja":
        import ofrak_capstone  # type: ignore
        import ofrak_binary_ninja  # type: ignore

        ofrak.injector.discover(ofrak_capstone)
        ofrak.injector.discover(ofrak_binary_ninja)

    elif backend == "ghidra":
        import ofrak_ghidra  # type: ignore

        ofrak.injector.discover(ofrak_ghidra)

    elif backend == "angr":
        import ofrak_angr  # type: ignore

        ofrak.injector.discover(ofrak_angr)

    else:
        LOGGER.warning("No disassembler backend specified, so no disassembly will be possible")

    ofrak.run(main, _host, _port)  # type: ignore
