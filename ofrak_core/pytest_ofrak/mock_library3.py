from ofrak.resource import ResourceFactory

from ofrak.model.component_model import ComponentExternalTool
from ofrak.service.component_locator_i import ComponentLocatorInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from pytest_ofrak.mock_component_types import MockUnpacker


class _MockComponentA(MockUnpacker):
    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        component_locator: ComponentLocatorInterface,
    ):
        super(MockUnpacker, self).__init__(
            resource_factory, data_service, resource_service, component_locator
        )

    external_dependencies = (ComponentExternalTool("tool_a", "tool_a.com", "--help", "tool_a_apt"),)


class _MockComponentB(MockUnpacker):
    external_dependencies = (
        ComponentExternalTool("tool_b", "tool_b.com", "--help", None, "tool_a_brew"),
    )


class _MockComponentC(MockUnpacker):
    pass
