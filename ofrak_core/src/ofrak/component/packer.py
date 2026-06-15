import logging
from abc import ABC, abstractmethod
from typing import Optional, Tuple

from ofrak.component.abstract import AbstractComponent
from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.modifier import Modifier
from ofrak.model.component_model import CC
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.component_locator_i import (
    ComponentLocatorInterface,
)
from ofrak.model.component_filters import (
    ComponentWhitelistFilter,
    ComponentTypeFilter,
    ComponentOrMetaFilter,
    ComponentAndMetaFilter,
    ComponentNotMetaFilter,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface

LOGGER = logging.getLogger(__name__)


class PackerError(RuntimeError):
    """Base exception raised by Packers."""


class Packer(AbstractComponent[CC], ABC):
    """
    Packers are components that typically mirror unpackers, taking constituent children resources
    (and sometimes descendants) and reassembling them to produce a new resource.
    """

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self._component_locator = component_locator

    @abstractmethod
    async def pack(self, resource: Resource, config: CC) -> None:
        """
        Pack the given resource.

        Users should not call this method directly; rather, they should run
        [Resource.run][ofrak.resource.Resource.run] or
        [Resource.pack][ofrak.resource.Resource.pack].

        :param resource:
        :param config: Optional config for packing. If an implementation provides a default,
        this default will always be used when config would otherwise be None. Note that a copy of
        the default config will be passed, so the default config values cannot be modified
        persistently by a component run.
        """
        raise NotImplementedError()

    @classmethod
    def get_default_config(cls) -> Optional[CC]:
        return cls._get_default_config_from_method(cls.pack)

    async def _run(self, resource: Resource, config: CC) -> None:
        if resource.has_component_run(self.get_id(), self.get_version()):
            LOGGER.warning(
                f"The {self.get_id().decode()} packer has already been run on resource"
                f" {resource.get_id().hex()}"
            )
            return
        await self.pack(resource, config)
        resource.add_component(self.get_id(), self.get_version())
        # Identify which unpackers ran (if any) and clear that record, so that it will be allowed
        # to run again
        unpacker_ids = self._get_which_unpackers_ran(resource)
        for unpacker_id in unpacker_ids:
            resource.remove_component(unpacker_id)
        for child_r in await resource.get_children():
            await child_r.delete()

    def _get_which_unpackers_ran(self, resource: Resource) -> Tuple[bytes, ...]:
        unpackers_ran = self._component_locator.get_components_matching_filter(
            ComponentAndMetaFilter(
                ComponentWhitelistFilter(*resource.get_model().component_versions.keys()),
                # Use process of elimination to avoid circular import between unpacker.py, packer.py
                ComponentNotMetaFilter(
                    ComponentOrMetaFilter(
                        ComponentTypeFilter(Packer),  # type: ignore
                        ComponentTypeFilter(Analyzer),  # type: ignore
                        ComponentTypeFilter(Identifier),  # type: ignore
                        ComponentTypeFilter(Modifier),  # type: ignore
                    )
                ),
            )
        )
        return tuple(unpacker.get_id() for unpacker in unpackers_ran)
