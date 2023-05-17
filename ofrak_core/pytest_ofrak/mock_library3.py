from ofrak.component.unpacker import Unpacker

from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.ofrak_context_interface import OFRAKContext2Interface
from pytest_ofrak.mock_component_types import MockUnpacker


class _MockComponentA(MockUnpacker):
    def __init__(self, ofrak_context: OFRAKContext2Interface):
        Unpacker.__init__(self, ofrak_context)

    external_dependencies = (ComponentExternalTool("tool_a", "tool_a.com", "--help", "tool_a_apt"),)


class _MockComponentB(MockUnpacker):
    external_dependencies = (
        ComponentExternalTool("tool_b", "tool_b.com", "--help", None, "tool_a_brew"),
    )


class _MockComponentC(MockUnpacker):
    pass
