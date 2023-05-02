from abc import ABC, abstractmethod
from typing import Generic, Optional, Tuple

from ofrak.model.component_model import CC, ComponentRunResult, ComponentExternalTool
from ofrak.model.tag_model import ResourceTag


class ComponentInterface(Generic[CC], ABC):
    """
    A component is responsible for modifying or create firmware resources. They are categorized
    as identifiers, unpackers, analyzers, modifiers and packers.
    """

    version: Optional[int] = None
    id: Optional[bytes] = None

    @classmethod
    @abstractmethod
    def get_default_config(cls) -> Optional[CC]:
        raise NotImplementedError()

    @abstractmethod
    def get_version(self) -> int:
        raise NotImplementedError()

    @property
    @abstractmethod
    def targets(self) -> Tuple[ResourceTag, ...]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def external_dependencies(self) -> Tuple[ComponentExternalTool, ...]:
        raise NotImplementedError()

    @abstractmethod
    async def run(
        self,
        job_id: bytes,
        resource_id: bytes,
        config: CC,
    ) -> ComponentRunResult:
        """

        :param job_id:
        :param resource_id:
        :param config:
        :return: The IDs of all resources modified by this component
        """
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_id(cls) -> bytes:
        raise NotImplementedError()
