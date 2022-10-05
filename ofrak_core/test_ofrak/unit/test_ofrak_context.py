import asyncio

import pytest

from ofrak import OFRAK, OFRAKContext


@pytest.fixture
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


def test_ofrak_context():
    """
    Test that OFRAK.run successfully creates an event loop and runs the target async function.
    """

    async def main(ofrak_context: OFRAKContext, binary: bytes):
        resource = await ofrak_context.create_root_resource("test_binary", binary)
        data = await resource.get_data()
        assert data == binary

    ofrak = OFRAK()
    ofrak.run(main, b"Hello world\n")
