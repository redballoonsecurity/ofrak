from abc import ABC, abstractmethod
from typing import Tuple, Optional, List

from ofrak.component.abstract import AbstractComponent
from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.modifier import Modifier
from ofrak.model.component_filters import (
    ComponentWhitelistFilter,
    ComponentTypeFilter,
    ComponentOrMetaFilter,
    ComponentAndMetaFilter,
    ComponentNotMetaFilter,
)
from ofrak.model.component_model import CC
from ofrak.model.tag_model import ResourceTag
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.component_locator_i import (
    ComponentLocatorInterface,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface


class UnpackerError(RuntimeError):
    """Base exception raised by unpackers."""


class Unpacker(AbstractComponent[CC], ABC):
    """
    Unpackers are components that unpack resources, splitting them into one or more children.
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

    @property
    @abstractmethod
    def children(self) -> Tuple[Optional[ResourceTag], ...]:
        """
        A list of [ResourceTags][ofrak.model.tag_model.ResourceTag] that an unpacker can unpack a
        resource into.
        """
        raise NotImplementedError()

    @abstractmethod
    async def unpack(self, resource: Resource, config: CC) -> None:
        """
        Unpack the given resource.

        Users should not call this method directly; rather, they should run
        [Resource.run][ofrak.resource.Resource.run] or
        [Resource.unpack][ofrak.resource.Resource.unpack].

        :param resource: The resource that is being unpacked
        :param config: Optional config for unpacking. If an implementation provides a default,
        this default will always be used when config would otherwise be None. Note that a copy of
        the default config will be passed, so the default config values cannot be modified
        persistently by a component run.
        """
        raise NotImplementedError()

    @classmethod
    def get_default_config(cls) -> Optional[CC]:
        return cls._get_default_config_from_method(cls.unpack)

    async def _run(self, resource: Resource, config: CC):
        if resource.has_component_run(self.get_id(), self.get_version()):
            return self._log_component_has_run_warning(resource)
        if resource.has_component_run(self.get_id()):
            self._log_component_has_run_warning(resource)
            raise NotImplementedError(
                "If the component has already run (but on a different "
                "version), we should remove the dependencies"
            )
        await self.unpack(resource, config)
        resource.add_component(self.get_id(), self.get_version())
        self._validate_unpacked_children(resource)
        # Identify which packers ran (if any) and clear that record, so that it will be allowed
        # to run again
        packer_ids = self._get_which_packers_ran(resource)
        for packer_id in packer_ids:
            resource.remove_component(packer_id)

    def _get_which_packers_ran(self, resource: Resource) -> Tuple[bytes, ...]:
        unpackers_ran = self._component_locator.get_components_matching_filter(
            ComponentAndMetaFilter(
                ComponentWhitelistFilter(*resource.get_model().component_versions.keys()),
                # Use process of elimination to avoid circular import between unpacker.py, packer.py
                ComponentNotMetaFilter(
                    ComponentOrMetaFilter(
                        ComponentTypeFilter(Unpacker),  # type: ignore
                        ComponentTypeFilter(Analyzer),  # type: ignore
                        ComponentTypeFilter(Identifier),  # type: ignore
                        ComponentTypeFilter(Modifier),  # type: ignore
                    )
                ),
            )
        )
        return tuple(unpacker.get_id() for unpacker in unpackers_ran)

    def _validate_unpacked_children(self, resource: Resource) -> None:
        """
        Validate that the unpacked resources match the type defined by
        [Unpacker.children][ofrak.component.unpacker.Unpacker.children].

        :param resource:
        :raises ValueError: if the unpacked child does not match the type defined in
          [Unpacker.children][ofrak.component.unpacker.Unpacker.children]
        """
        component_context = resource.get_component_context()
        resource_context = resource.get_resource_context()
        untagged_descendants_allowed = None in self.children
        for descendant_id in component_context.resources_created:
            descendant_model = resource_context.resource_models.get(descendant_id)
            if descendant_model is None:
                raise ValueError(
                    f"Cannot find descendant {descendant_id.decode()} for resource "
                    f"{resource.get_id().decode()}."
                )
            descendant_has_tags = 0 != len(descendant_model.get_tags())

            if descendant_has_tags:
                if any(
                    descendant_model.has_tag(descendant_tag)
                    for descendant_tag in self.children
                    if descendant_tag is not None
                ):
                    continue
                else:
                    valid_tag_patterns: List[str] = [
                        descendant_tag.__name__
                        for descendant_tag in self.children
                        if descendant_tag is not None
                    ]
                    if untagged_descendants_allowed:
                        valid_tag_patterns.append("untagged resource")
                    expected_patterns = ", ".join(valid_tag_patterns)

                    raise ValueError(
                        f"Unpacker {self.get_id().decode()} created resource {descendant_id.hex()} "
                        f"but its tags {descendant_model.get_tags()} do not match any of the "
                        f"expected patterns this unpacker should create: {expected_patterns}"
                    )
            elif untagged_descendants_allowed:
                continue
            else:
                raise ValueError(
                    f"Unpacker {self.get_id().decode()} created resource {descendant_id.hex()} but "
                    f"its tags {descendant_model.get_tags()} do not match any of the expected "
                    f"patterns this unpacker should create: "
                    f"{', '.join([str(descendant_tag) for descendant_tag in self.children])}"
                )
