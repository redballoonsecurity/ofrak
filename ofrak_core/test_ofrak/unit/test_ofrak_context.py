import asyncio

from ofrak import OFRAK, OFRAKContext


def test_ofrak_context():
    """
    Test that OFRAK.run successfully creates an event loop and runs the target async function.
    """
    # Reset the event loop (this appears to be necessary when running in CI)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def main(ofrak_context: OFRAKContext, binary: bytes):
        resource = await ofrak_context.create_root_resource("test_binary", binary)
        data = await resource.get_data()
        assert data == binary

    ofrak = OFRAK()
    ofrak.run(main, b"Hello world\n")
