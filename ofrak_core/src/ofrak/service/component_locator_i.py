from abc import ABCMeta, abstractmethod, ABC
from types import ModuleType
from typing import List, Type, Optional, TypeVar, Set

from dataclasses import dataclass

from ofrak.component.interface import ComponentInterface

CI = TypeVar("CI", bound="ComponentInterface")


# MyPy shows a type error on the next line, root cause unknown:
# error: Only concrete class can be given where "Type[ComponentFilter]" is expected
@dataclass(frozen=True, init=False)  # type: ignore
class ComponentFilter(ABC):
    @abstractmethod
    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        """
        Filter out components according to the rules this component enforces.

        :param components: Components to filter

        :return: All components which this filter allows
        """
        raise NotImplementedError()


class ComponentLocatorInterface(metaclass=ABCMeta):
    @abstractmethod
    def add_components(
        self,
        components: List[ComponentInterface],
        module_priority: Optional[List[ModuleType]] = None,
    ):
        pass

    @abstractmethod
    def get_by_id(self, component_id: bytes) -> ComponentInterface:
        pass

    @abstractmethod
    def get_by_type(self, component_type: Type[CI]) -> CI:
        pass

    @abstractmethod
    def get_components_matching_filter(
        self, component_filter: ComponentFilter
    ) -> Set[ComponentInterface]:
        """
        Get all components matching the given filter.
        """
