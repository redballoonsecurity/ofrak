import asyncio
from typing import Mapping, Sequence, Type, Tuple
import sys
import pytest

from ofrak.model.component_model import ComponentExternalTool
from ofrak.component.abstract import AbstractComponent


async def _check_deps_installed(
    deps: Sequence[ComponentExternalTool],
) -> Mapping[ComponentExternalTool, bool]:
    return dict(zip(deps, await asyncio.gather(*(dep.is_tool_installed() for dep in deps))))


def _handle_skipif_missing_deps(
    deps_installed_data: Mapping[ComponentExternalTool, bool],
    components: Sequence[Type[AbstractComponent]],
) -> Tuple[bool, str]:
    """
    :param deps_installed_data: a precomputed mapping of all tools to their installed status
    :params components: the components a test case uses

    :return: a ``skipif`` marker for skipping a test function, module, or class if not all
    dependencies of a component are satisfied.
    """

    missing_messages = []
    skip = False
    for component in components:
        missing = [
            dep.tool for dep in component.external_dependencies if not deps_installed_data[dep]
        ]
        if missing:
            skip = True
            missing_messages.append(f"{', '.join(missing)} of {component.__name__}")
    return pytest.mark.skipif(
        skip, reason=f"Missing external dependencies: {'; '.join(missing_messages)}"
    )


# https://docs.pytest.org/en/latest/example/simple.html#control-skipping-of-tests-according-to-command-line-option
def pytest_addoption(parser):
    parser.addoption(
        "--skip-tests-missing-deps",
        action="store_true",
        default=False,
        help="skip tests whose required external dependencies are missing",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        (
            "skipif_missing_deps(component_classes): skip the test function, module, or class if not all dependencies of a component class(es) are installed. "
            "This marker has to take an iterable of classes rather than args otherwise pytest's decorator magic will think the mark was applied to the component "
            "class not the actual test function. "
            "Example: @skipif_missing_deps([StringsAnalyzer]) would skip a test if the linux `strings` command is unavailable because StringsAnalyzer calls `strings`."
        ),
    )
    config.addinivalue_line(
        "markers",
        "skipif_windows: skip the test if running on windows. Equivalent to @skipif(sys.platform == 'win32')",
    )


def _all_required_components(item) -> Sequence[Type[AbstractComponent]]:
    return [
        component
        for mark in item.iter_markers(name="skipif_missing_deps")
        for component in mark.args[0]
    ]


def pytest_collection_modifyitems(config, items):
    if config.getoption("--skip-tests-missing-deps"):
        deps_installed_data = asyncio.run(
            _check_deps_installed(
                {
                    dep
                    for item in items
                    for component in _all_required_components(item)
                    for dep in component.external_dependencies
                }
            )
        )

        for item in items:
            if components := _all_required_components(item):
                item.add_marker(_handle_skipif_missing_deps(deps_installed_data, components))

    if sys.platform == "win32":
        windows_skip_marker = pytest.mark.skip(reason="Test cannot run on Windows.")

        for item in items:
            if "skipif_windows" in item.keywords:
                item.add_marker(windows_skip_marker)
