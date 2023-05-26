import asyncio
import logging

import pytest

from ofrak import OFRAK, OFRAKContext
from ofrak.core.apk import ApkIdentifier
from ofrak.ofrak_context import get_current_ofrak_context
from ofrak_type.error import NotFoundError, InvalidStateError
from pytest_ofrak import mock_library3
from pytest_ofrak.mock_library3 import _MockComponentA


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


def test_ofrak_context_exclude_components_missing_dependencies():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def run_component_with_bad_dependency(ofrak_context: OFRAKContext):
        resource = await ofrak_context.create_root_resource("test_binary", b"")
        await resource.run(_MockComponentA)

    async def run_component_with_installed_dependency(ofrak_context: OFRAKContext):
        resource = await ofrak_context.create_root_resource("test_binary", b"")
        await resource.run(ApkIdentifier)

    ofrak = OFRAK(logging_level=logging.WARNING, exclude_components_missing_dependencies=True)
    ofrak.discover(mock_library3)

    ofrak.run(run_component_with_installed_dependency)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    with pytest.raises(NotFoundError):
        ofrak.run(run_component_with_bad_dependency)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    ofrak = OFRAK(logging_level=logging.WARNING, exclude_components_missing_dependencies=False)
    ofrak.discover(mock_library3)
    ofrak.run(run_component_with_bad_dependency)


def test_get_ofrak_context_over_time():
    # No active context before running OFRAK
    with pytest.raises(InvalidStateError):
        get_current_ofrak_context()

    ofrak = OFRAK()

    async def foo(ofrak_context):
        # Active context while in script
        current_ofrak_context = get_current_ofrak_context()
        assert current_ofrak_context is not None
        assert current_ofrak_context is ofrak_context

    ofrak.run(foo)

    # No active context after script finishes
    with pytest.raises(InvalidStateError):
        get_current_ofrak_context()


async def test_get_ofrak_context_fixture(ofrak_context: OFRAKContext):
    current_ofrak_context = get_current_ofrak_context()
    assert current_ofrak_context is not None
    assert current_ofrak_context is ofrak_context
