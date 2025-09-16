import sys

from ofrak.model.component_model import ComponentExternalTool
from pytest_ofrak.mock_component_types import MockRunnableUnpacker


class _MockComponentA(MockRunnableUnpacker):
    external_dependencies = (ComponentExternalTool("tool_a", "tool_a.com", "--help", "tool_a_apt"),)


class _MockComponentB(MockRunnableUnpacker):
    external_dependencies = (
        ComponentExternalTool("tool_b", "tool_b.com", "--help", None, "tool_a_brew"),
    )


class _MockComponentC(MockRunnableUnpacker):
    pass


class _MockComponentSysExec(MockRunnableUnpacker):
    external_dependencies = (ComponentExternalTool(sys.executable, "", "--version", None, ""),)
