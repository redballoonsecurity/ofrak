"""
Test the core functionality of the OFRAK context, including
OFRAK.run behavior, context management, and resource creation.
"""
import asyncio
import logging

import pytest
from tempfile import TemporaryDirectory
import os
from ofrak import OFRAK, OFRAKContext
from ofrak.resource import Resource
from ofrak.ofrak_context import get_current_ofrak_context
from ofrak_type.error import NotFoundError, InvalidStateError
from pytest_ofrak import mock_library3
from pytest_ofrak.mock_library3 import _MockComponentA, _MockComponentSysExec

from ofrak.core.filesystem import FilesystemRoot


def test_ofrak_context():
    """
    Test that OFRAK.run successfully creates an event loop and runs the target async function.

    This test verifies that:
    - OFRAK.run can create and manage an event loop
    - The provided async function executes correctly within the context
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
    """
    Test the exclusion of components with missing dependencies.

    This test verifies that:
    - Components with missing dependencies are excluded when configured to do so
    - Components with installed dependencies can be executed
    - Components with missing dependencies raise NotFoundError when excluded
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def run_component_with_bad_dependency(ofrak_context: OFRAKContext):
        resource = await ofrak_context.create_root_resource("test_binary", b"")
        await resource.run(_MockComponentA)

    async def run_component_with_installed_dependency(ofrak_context: OFRAKContext):
        resource = await ofrak_context.create_root_resource("test_binary", b"")
        await resource.run(_MockComponentSysExec)

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
    """
    Test context management over the lifetime of OFRAK execution.

    This test verifies that:
    - No active context exists before running OFRAK
    - An active context is available during OFRAK execution
    - No active context exists after OFRAK execution completes
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

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
    """
    Test that the ofrak_context fixture provides a valid OFRAK context.

    This test verifies that:
    - The fixture correctly provides an OFRAK context
    - The context retrieved via get_current_ofrak_context matches the fixture-provided context
    """
    current_ofrak_context = get_current_ofrak_context()
    assert current_ofrak_context is not None
    assert current_ofrak_context is ofrak_context


async def test_create_root_resource_from_directory(ofrak_context: OFRAKContext):
    """
    Test creating a root resource from a directory structure.

    This test verifies that:
    - A directory can be converted into a root resource
    - The directory structure and file contents are preserved
    - The created resource can be flushed back to disk maintaining integrity
    """
    with TemporaryDirectory() as tempdir:
        with open(os.path.join(tempdir, "1.txt"), "w") as fh:
            fh.write("test")
        with open(os.path.join(tempdir, "2.txt"), "w") as fh:
            fh.write("test2")
        os.mkdir(os.path.join(tempdir, "test3"))
        with open(os.path.join(tempdir, os.path.join("test3", "test3.txt")), "w") as fh:
            fh.write("test3")
        orig_files = []
        orig_dirs = []
        for _, dirs, files in os.walk(tempdir):
            orig_dirs.append(dirs)
            orig_files.append(files)
        root_resource: Resource = await ofrak_context.create_root_resource_from_directory(tempdir)
    with TemporaryDirectory() as tempdir:
        root_v = await root_resource.view_as(FilesystemRoot)
        await root_v.flush_to_disk(tempdir)
        res = os.walk(tempdir)
        new_files = []
        new_dirs = []
        for _, dirs, files in os.walk(tempdir):
            new_dirs.append(dirs)
            new_files.append(files)
        assert orig_dirs == new_dirs
        assert orig_files == new_files
