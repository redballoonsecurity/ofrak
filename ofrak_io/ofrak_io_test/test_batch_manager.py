import asyncio
import random
from dataclasses import dataclass
from typing import Tuple, Iterable

import pytest

from ofrak.model.data_model import DataModel
from ofrak.service.data_service import DataService
from ofrak.service.data_service_i import DataServiceInterface
from ofrak_io.batch_manager import (
    NotAllRequestsHandledError,
    AbstractBatchManager,
    make_batch_manager,
    BatchManagerInterface,
)


@dataclass
class Counter:
    count: int


@pytest.fixture
def many_strings():
    def random_string():
        return "".join([chr(random.choice(range(0, 256))) for _ in range(random.randint(3, 15))])

    return [random_string() for _ in range(1000)]


@pytest.fixture
def counter():
    return Counter(0)


@pytest.fixture
def data_service():
    return DataService()


def batch_manager_with_function(counter):
    async def handle_requests(requests: Tuple[str, ...]) -> Iterable[Tuple[str, int]]:
        await asyncio.sleep(1)
        results = [(req, len(req)) for req in requests]
        counter.count += 1
        return results

    return make_batch_manager(handle_requests)


def batch_manager_with_subclass(counter):
    class TestBatchManager(AbstractBatchManager[str, int]):
        async def handle_requests(self, requests: Tuple[str, ...]) -> Iterable[Tuple[str, int]]:
            await asyncio.sleep(1)
            results = [(req, len(req)) for req in requests]
            counter.count += 1
            return results

    return TestBatchManager()


@pytest.fixture(params=(batch_manager_with_function, batch_manager_with_subclass))
def batch_manager(request, counter):
    return request.param(counter)


@pytest.fixture
def bad_batch_manager(counter):
    async def handle_requests(requests: Tuple[str, ...]) -> Iterable[Tuple[str, int]]:
        await asyncio.sleep(1)
        return []

    return make_batch_manager(handle_requests)


def data_service_batch_manager_with_function(data_service: DataServiceInterface):
    async def handle_requests(requests: Tuple[bytes, ...]) -> Iterable[Tuple[bytes, DataModel]]:
        return zip(requests, await data_service.get_by_ids(requests))

    return make_batch_manager(handle_requests)


def data_service_batch_manager_with_subclass(data_service: DataServiceInterface):
    class GetDataIdBatchManager(AbstractBatchManager[bytes, DataModel]):
        async def handle_requests(
            self, requests: Tuple[bytes, ...]
        ) -> Iterable[Tuple[bytes, DataModel]]:
            return zip(requests, await data_service.get_by_ids(requests))

    return GetDataIdBatchManager()


@pytest.fixture(
    params=(data_service_batch_manager_with_function, data_service_batch_manager_with_subclass)
)
def data_service_batch_manager(request, data_service):
    return request.param(data_service)


async def test_single_result(batch_manager, counter):
    test_string = "OFRAk is awesome"
    res = await batch_manager.get_result(test_string)
    assert res == len(test_string)
    assert counter.count == 1


async def test_many_results(batch_manager, many_strings, counter):
    await asyncio.gather(*[batch_manager.get_result(s) for s in many_strings])
    assert counter.count == 1


async def test_incomplete_handling_raises_err(bad_batch_manager):
    test_string = "OFRAk is awesome"
    with pytest.raises(NotAllRequestsHandledError):
        res = await bad_batch_manager.get_result(test_string)


async def test_batch_data_service_accesses(
    data_service: DataServiceInterface, data_service_batch_manager, many_strings
):
    expected_models = dict()
    for s in many_strings:
        data_id = int.to_bytes(abs(hash(s)), 8, "little")
        data = s.encode("UTF-8")

        m = await data_service.create(data_id, data)
        expected_models[data_id] = m

    tasks = []
    for data_id, expected_m in expected_models.items():

        async def _check():
            m = await data_service_batch_manager.get_result(data_id)
            assert m == expected_m

        tasks.append(_check())

    await asyncio.gather(*tasks)


# TODO: Figure out why line coverage is not ignoring the abstractmethod
async def test_raises_notimplemented():
    with pytest.raises(NotImplementedError):
        await AbstractBatchManager.handle_requests(None, ())

    with pytest.raises(NotImplementedError):
        await BatchManagerInterface.get_result(None, None)
