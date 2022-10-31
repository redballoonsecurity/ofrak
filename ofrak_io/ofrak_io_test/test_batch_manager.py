import asyncio
import random
from dataclasses import dataclass
from typing import Tuple, Iterable

import pytest

from ofrak_io.batch_manager import (
    NotAllRequestsHandledError,
    AbstractBatchManager,
    make_batch_manager,
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
        _ = await bad_batch_manager.get_result(test_string)
