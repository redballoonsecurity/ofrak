import asyncio
from typing import Mapping, Sequence, Type
import os
import pytest

from ofrak.model.component_model import ComponentExternalTool
from ofrak.component.abstract import AbstractComponent


def skipif_windows():
    return pytest.mark.skipif(os.name == "nt", reason="Test cannot run on Windows.")


async def uninstalled_deps(component: Type[AbstractComponent]) -> Sequence[ComponentExternalTool]:
    installed = await asyncio.gather(
        *(dep.is_tool_installed() for dep in component.external_dependencies)
    )
    return [
        dep for dep, installed in zip(component.external_dependencies, installed) if not installed
    ]


async def all_uninstalled_deps(
    components: Sequence[Type[AbstractComponent]],
) -> Mapping[Type[AbstractComponent], Sequence[ComponentExternalTool]]:
    uninstalled = await asyncio.gather(*(uninstalled_deps(component) for component in components))
    return {component: deps for component, deps in zip(components, uninstalled) if deps}


def requires_deps_of(*args: Type[AbstractComponent]):
    """
    pytest mark for skipping test function, module, or class if not all dependencies of a component
    are satisfied.
    """

    uninstalled_data = asyncio.run(all_uninstalled_deps(args))
    reason = "Missing deps:\n"
    if uninstalled_data:
        for component, deps in uninstalled_data.items():
            reason += f"{', '.join(dep.tool for dep in deps)} of {component.__name__ }"
    return pytest.mark.skipif(uninstalled_data, reason=reason)
