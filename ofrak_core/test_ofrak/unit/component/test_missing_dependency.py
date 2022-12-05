import os.path
import subprocess

import pytest

from ofrak import Unpacker, OFRAKContext
from ofrak.component.abstract import ComponentMissingDependencyError
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.job_model import JobRunContext
from ofrak.model.resource_model import ResourceContext
from ofrak.model.viewable_tag_model import ResourceViewContext


async def test_missing_dependency_caught(ofrak_context: OFRAKContext, tmpdir):
    dependency_path = os.path.join(tmpdir, "made_up_ofrak_dependency")

    class _MockComponent(Unpacker):
        targets = ()
        children = ()

        external_dependencies = (ComponentExternalTool(dependency_path, "", ""),)

        async def unpack(self, resource, config=None):
            subprocess.run(dependency_path)
            return

    root = await ofrak_context.create_root_resource("any", b"")
    unpacker = _MockComponent(
        ofrak_context.resource_factory,
        ofrak_context.data_service,
        ofrak_context.resource_service,
        ofrak_context.component_locator,
    )
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
