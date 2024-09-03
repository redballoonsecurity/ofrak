import asyncio
import logging

import pytest
from tempfile import TemporaryDirectory
import os
from ofrak import OFRAK, OFRAKContext
from ofrak.core.apk import ApkIdentifier
from ofrak.resource import Resource
from ofrak.ofrak_context import get_current_ofrak_context
from ofrak_type.error import NotFoundError, InvalidStateError
from pytest_ofrak import mock_library3
from pytest_ofrak.mock_library3 import _MockComponentA

from ofrak.core.filesystem import FilesystemRoot

from ofrak.model.component_model import ComponentExternalTool
from ofrak.core.squashfs import _UnsquashfsV45Tool
from ofrak.core.strings_analyzer import _StringsToolDependency


@pytest.mark.asyncio
async def test_path_auth_error(monkeypatch, caplog):
    if os.name != "posix":
        LOGGER.warning("test_path_auth_error is currently only supported by POSIX systems.")
        return

    monkeypatch.setenv("PATH", "/root")

    for tool in (
        ComponentExternalTool("apktool", "", "-version"),
        _UnsquashfsV45Tool(),
        _StringsToolDependency(),
    ):
        assert not await tool.is_tool_installed()
        expected = f"Encountered PermissionError while searching PATH for {tool.tool}."
        found = [r for r in caplog.records if r.message == expected]
        assert any(
            r.message == expected for r in caplog.records
        ), f"Missing error message from {tool.tool}"


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
    current_ofrak_context = get_current_ofrak_context()
    assert current_ofrak_context is not None
    assert current_ofrak_context is ofrak_context


async def test_create_root_resource_from_directory(ofrak_context: OFRAKContext):
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
