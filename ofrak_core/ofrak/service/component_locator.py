import logging
from types import ModuleType
from typing import List, Type, Dict, TypeVar, Optional, Set

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.interface import ComponentInterface
from ofrak.component.modifier import Modifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.service.component_locator_i import ComponentLocatorInterface, ComponentFilter
from ofrak_type.error import NotFoundError

LOGGER = logging.getLogger(__name__)
CI = TypeVar("CI", bound="ComponentInterface")


class InvalidComponentError(RuntimeError):
    pass


class TooFewConstraintsError(RuntimeError):
    pass


class ComponentLocator(ComponentLocatorInterface):
    """
    Locates component singletons from their types or `id`.
    """

    COMPONENT_CATEGORIES = (
        Unpacker,
        Packer,
        Analyzer,
        Modifier,
        Identifier,
    )

    def __init__(self):
        self._components_by_category: Dict[Type[ComponentInterface], List[ComponentInterface]] = {
            category: list() for category in ComponentLocator.COMPONENT_CATEGORIES
        }
        self._components_by_id: Dict[bytes, ComponentInterface] = {}

    def _resolve_id_conflict(
        self,
        component_a: ComponentInterface,
        component_b: ComponentInterface,
        module_priority: List[ModuleType],
    ) -> ComponentInterface:
        contested_id = component_a.get_id()
        if component_a == component_b:
            return component_a
        component_a_name = type(component_a).__name__
        component_b_name = type(component_b).__name__

        for module in reversed(module_priority):
            component_a_in_module = all(
                m1 == m2
                for m1, m2 in zip(component_a.__module__.split("."), module.__name__.split("."))
            )
            component_b_in_module = all(
                m1 == m2
                for m1, m2 in zip(component_b.__module__.split("."), module.__name__.split("."))
            )

            if component_a_in_module:
                LOGGER.debug(
                    f"Component ID conflict for {contested_id.decode()} between "
                    f"{component_a_name} and {component_b_name} "
                    f"resolved: {component_a_name}'s module is higher "
                    f"priority, {component_b_name} will not be used."
                )
                return component_a
            elif component_b_in_module:
                LOGGER.debug(
                    f"Component ID conflict for {contested_id.decode()} between "
                    f"{component_a_name} and {component_b_name} "
                    f"resolved: {component_b_name}'s module is higher "
                    f"priority, {component_a_name} will not be used."
                )
                return component_b

        raise InvalidComponentError(
            f"A component with the ID {contested_id.decode()} is already "
            f"registered and given module priorities were insufficient to resolve conflict"
        )

    def add_components(
        self,
        components: List[ComponentInterface],
        module_priority: Optional[List[ModuleType]] = None,
    ):
        for component in components:
            if component.get_id() not in self._components_by_id:
                self._components_by_id[component.get_id()] = component
            else:
                if module_priority is None:
                    raise InvalidComponentError(
                        f"A component with the ID {component.get_id().decode()} is already "
                        f"registered"
                    )
                else:
                    contested_id = component.get_id()
                    existing_component = self._components_by_id[contested_id]

                    self._components_by_id[contested_id] = self._resolve_id_conflict(
                        component, existing_component, module_priority
                    )

        for component in self._components_by_id.values():
            component_category = None
            for t_component_type in self._components_by_category.keys():
                if isinstance(component, t_component_type):
                    component_category = t_component_type
                    break
            if component_category is None:
                category_names = [category.__name__ for category in self.COMPONENT_CATEGORIES]
                raise InvalidComponentError(
                    f"The component {component.get_id().decode()} is not one of {', '.join(category_names)}"
                )
            if component.targets is None:
                raise InvalidComponentError(
                    f"The component {component.get_id().decode()} does not define targets"
                )
            if component.get_version() is None:
                raise InvalidComponentError(
                    f"The component {component.get_id().decode()} does not define a version"
                )
            if isinstance(component, Analyzer):
                if component.outputs is None:
                    raise InvalidComponentError(
                        f"The analyzer {component.get_id().decode()} does not define attributes"
                    )

            self._components_by_category[component_category].append(component)
            LOGGER.debug(
                f"Registered component {component.get_id().decode()} as {component_category.__name__}"
            )

    def get_by_id(self, component_id: bytes) -> ComponentInterface:
        component = self._components_by_id.get(component_id)
        if component is None:
            raise NotFoundError(
                f"The component with ID {component_id.decode()} has not been registered"
            )
        return component

    def get_by_type(self, component_type: Type[CI]) -> CI:
        return self.get_by_id(component_type.get_id())  # type: ignore

    def get_components_matching_filter(
        self, component_filter: ComponentFilter
    ) -> Set[ComponentInterface]:
        # naive implementation to start
        # will be improved by caching
        components = set(self._components_by_id.values())

        return component_filter.filter(components)
