import os.path
import subprocess

import pytest

from ofrak import Unpacker, OFRAKContext
from ofrak.component.abstract import ComponentMissingDependencyError, ComponentSubprocessError
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.ofrak_context_interface import OFRAKContext2Interface


@pytest.fixture()
def dependency_path(tmpdir):
    return os.path.join(tmpdir, "made_up_ofrak_dependency")


@pytest.fixture()
def mock_dependency(dependency_path):
    return ComponentExternalTool(dependency_path, "", "")


@pytest.fixture()
def bad_dependency():
    # Use known bad flag that will return a non-zero exit code
    return ComponentExternalTool("ls", "", "-1234")


async def test_missing_external_tool_caught(
    ofrak_context: OFRAKContext2Interface, dependency_path, mock_dependency, ofrak_injector
):
    class _MockComponent(Unpacker):
        targets = ()
        children = ()

        external_dependencies = (mock_dependency,)

        async def unpack(self, resource, config=None):
            subprocess.run(dependency_path, check=True)
            return

    unpacker = _MockComponent(
        ofrak_context,
    )

    root = await ofrak_context.create_root_resource("any", b"")
    with pytest.raises(ComponentMissingDependencyError):
        await unpacker.run(
            b"test job",
            root.get_id(),
            None,
        )

    # The dependency will no longer be "missing"
    with open(dependency_path, "w+") as f:
        f.write("x")

    # It will still raise an error since the text file can't be executed
    # but it won't be a ComponentMissingDependencyError
    with pytest.raises(OSError):
        await unpacker.run(
            b"test job",
            root.get_id(),
            None,
        )


async def test_external_tool_runtime_error_caught(ofrak_context: OFRAKContext, tmpdir):
    class _MockComponent(Unpacker):
        targets = ()
        children = ()

        async def unpack(self, resource, config=None):
            subprocess.run(["cat", os.path.join(tmpdir, "nonexistant_file")], check=True)
            return

    unpacker = _MockComponent(ofrak_context)

    root = await ofrak_context.create_root_resource("any", b"")
    with pytest.raises(ComponentSubprocessError):
        await unpacker.run(
            b"test job",
            root.get_id(),
            None,
        )


async def test_tool_install_check(mock_dependency):
    assert not await mock_dependency.is_tool_installed()

    echo_tool = ComponentExternalTool("echo", "", install_check_arg=".")
    assert await echo_tool.is_tool_installed()


async def test_bad_tool_install_check(bad_dependency):
    assert not await bad_dependency.is_tool_installed()
