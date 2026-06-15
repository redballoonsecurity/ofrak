"""
Test the batch manager functionality.
"""
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
    """
    Test that a single request is handled correctly by the batch manager.

    This test verifies that:
    - A single string request is processed and returns the correct result
    - The batch manager properly tracks the number of batches handled
    """
    test_string = "OFRAk is awesome"
    res = await batch_manager.get_result(test_string)
    assert res == len(test_string)
    assert counter.count == 1


async def test_many_results(batch_manager, many_strings, counter):
    """
    Test that multiple requests are handled efficiently by the batch manager.

    This test verifies that:
    - Multiple string requests are processed in a single batch
    - The batch manager correctly tracks batch handling for multiple requests
    """
    await asyncio.gather(*[batch_manager.get_result(s) for s in many_strings])
    assert counter.count == 1


async def test_incomplete_handling_raises_err(bad_batch_manager):
    """
    Test that the batch manager properly raises an error when not all requests are handled.

    This test verifies that:
    - A NotAllRequestsHandledError is raised when some requests are not processed
    """
    test_string = "OFRAk is awesome"
    with pytest.raises(NotAllRequestsHandledError):
        _ = await bad_batch_manager.get_result(test_string)
