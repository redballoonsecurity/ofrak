import asyncio
import logging
from typing import Tuple

from ofrak import OFRAK, OFRAKContext
from ofrak.resource import Resource


def test_ofrak_context():
    """
    Test job server can handle start and stop. Should cause a warning to be printed about running the identifiers twice.
    """

    ofrak = OFRAK(logging_level=logging.INFO)

    async def step1(binary: bytes) -> Tuple[Resource, OFRAKContext]:
        ofrak_context = await ofrak.create_ofrak_context()
        resource = await ofrak_context.create_root_resource("test_binary", binary)
        await resource.identify()
        return resource, ofrak_context

    resource, ofrak_context = asyncio.get_event_loop().run_until_complete(step1(b"Hello world\n"))
    assert ofrak_context.job_service._num_runners == 0
    assert len(ofrak_context.job_service._active_component_tasks) == 0

    async def step2(resource):
        await resource.identify()

    asyncio.get_event_loop().run_until_complete(step2(resource))
    assert ofrak_context.job_service._num_runners == 0
    assert len(ofrak_context.job_service._active_component_tasks) == 0
