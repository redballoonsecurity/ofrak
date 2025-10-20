"""
Test functionality related to external tool dependencies in components.
"""
import os.path
import subprocess
import os
import sys

import pytest

from ofrak import Unpacker, OFRAKContext
from ofrak.component.abstract import ComponentMissingDependencyError, ComponentSubprocessError
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.job_model import JobRunContext
from ofrak.model.resource_model import ResourceContext
from ofrak.model.viewable_tag_model import ResourceViewContext


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
    ofrak_context: OFRAKContext, dependency_path, mock_dependency
):
    """
    This test verifies that a component properly handles missing external tool dependencies.

    This test verifies that:
    - A ComponentMissingDependencyError is raised when an external tool dependency is not found
    - An OSError is raised when the dependency exists but cannot be executed
    """

    class _MockComponent(Unpacker):
        targets = ()
        children = ()

        external_dependencies = (mock_dependency,)

        async def unpack(self, resource, config=None):
            subprocess.run(dependency_path, check=True)
            return

    unpacker = _MockComponent(
        ofrak_context.resource_factory,
        ofrak_context.data_service,
        ofrak_context.resource_service,
        ofrak_context.component_locator,
    )

    root = await ofrak_context.create_root_resource("any", b"")
    with pytest.raises(ComponentMissingDependencyError):
        await unpacker.run(
            b"test job",
            root.get_id(),
            JobRunContext(),
            ResourceContext(dict()),
            ResourceViewContext(),
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
            JobRunContext(),
            ResourceContext(dict()),
            ResourceViewContext(),
            None,
        )


async def test_external_tool_runtime_error_caught(ofrak_context: OFRAKContext, tmpdir):
    """
    This test verifies that a component properly handles runtime errors from external tools.

    This test verifies that:
    - A ComponentSubprocessError is raised when an external tool fails during execution
    """

    class _MockComponent(Unpacker):
        targets = ()
        children = ()

        async def unpack(self, resource, config=None):
            subprocess.run([sys.executable, os.path.join(tmpdir, "nonexistent_script")], check=True)
            return

    unpacker = _MockComponent(
        ofrak_context.resource_factory,
        ofrak_context.data_service,
        ofrak_context.resource_service,
        ofrak_context.component_locator,
    )

    root = await ofrak_context.create_root_resource("any", b"")
    with pytest.raises(ComponentSubprocessError):
        await unpacker.run(
            b"test job",
            root.get_id(),
            JobRunContext(),
            ResourceContext(dict()),
            ResourceViewContext(),
            None,
        )


async def test_tool_install_check(mock_dependency):
    """
    This test verifies the functionality of checking if an external tool is installed.

    This test verifies that:
    - A tool that does not exist is correctly identified as not installed
    - A tool with a valid install check argument is correctly identified as installed
    """
    assert not await mock_dependency.is_tool_installed()

    cd_tool = ComponentExternalTool(sys.executable, "", install_check_arg="-v")
    assert await cd_tool.is_tool_installed()


async def test_bad_tool_install_check(bad_dependency):
    """
    This test verifies the behavior when checking a tool that is known to fail its install check.

    This test verifies that:
    - A tool with an invalid install check argument is correctly identified as not installed
    """
    assert not await bad_dependency.is_tool_installed()
