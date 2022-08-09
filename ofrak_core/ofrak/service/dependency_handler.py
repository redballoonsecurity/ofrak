import logging
from typing import Set, List, Iterable, Dict, cast

from ofrak.model.component_model import ComponentContext
from ofrak.model.data_model import DataPatchesResult
from ofrak.model.resource_model import (
    ResourceContext,
    ResourceAttributeDependency,
    MutableResourceModel,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type.range import Range

LOGGER = logging.getLogger(__file__)


class DependencyHandler:
    """
    Stateless handler for dealing with creating and invalidating dependencies. Intended for
    one-time use in a component, or possible re-use in a resource.
    """

    def __init__(
        self,
        resource_service: ResourceServiceInterface,
        data_service: DataServiceInterface,
        component_context: ComponentContext,
        resource_context: ResourceContext,
    ):
        self._resource_service = resource_service
        self._data_service = data_service
        self._component_context = component_context
        self._resource_context = resource_context

    async def _map_data_ids_to_resources(
        self, data_ids: Iterable[bytes]
    ) -> Dict[bytes, MutableResourceModel]:
        resources_by_data_id = dict()
        for resource_id, resource_m in self._resource_context.resource_models.items():
            if resource_m.data_id is not None:
                resources_by_data_id[resource_m.data_id] = resource_m

        missing_data_ids = set()
        for data_id in data_ids:
            if data_id not in resources_by_data_id:
                missing_data_ids.add(data_id)

        missing_resources = await self._resource_service.get_by_data_ids(missing_data_ids)
        for missing_resource in missing_resources:
            missing_resource_data_id = cast(bytes, missing_resource.data_id)
            if missing_resource_data_id in resources_by_data_id:
                raise ValueError("Something is wrong in the implementation")
            mutable_resource = MutableResourceModel.from_model(missing_resource)
            resources_by_data_id[missing_resource_data_id] = mutable_resource
            self._resource_context.resource_models[missing_resource.id] = mutable_resource

        return resources_by_data_id

    async def handle_post_patch_dependencies(self, patch_results: List[DataPatchesResult]):
        # Create look up maps for resources and dependencies
        resources_by_data_id = await self._map_data_ids_to_resources(
            patch_result.data_id for patch_result in patch_results
        )

        unhandled_dependencies: Set[ResourceAttributeDependency] = set()
        # Figure out which components results must be invalidated based on data changes

        for data_patch_result in patch_results:
            resource_m = resources_by_data_id[data_patch_result.data_id]
            removed_data_dependencies = set()
            # Iterate over the resource's data dependencies to find one that's affected by one of
            # the patch range
            for dependency, dependency_ranges in resource_m.data_dependencies.items():
                # Iterate over the resource's data dependency ranges to find a range that overlaps
                # the patch range
                for dependency_range in dependency_ranges:
                    for patch in data_patch_result.patches:
                        if not dependency_range.overlaps(patch.range):
                            continue
                        LOGGER.debug(
                            f"Invalidating results of {dependency.component_id!r} on resource "
                            f"{dependency.dependent_resource_id.hex()} due to a data change on "
                            f"resource {resource_m.id.hex()}"
                        )
                        # That dependency is invalid, we can move on to the next dependency
                        unhandled_dependencies.add(dependency)
                        removed_data_dependencies.add(dependency)
                        break
                    # If a previous dependency range was found to affect the dependency, no need to
                    # continue iterating the ranges
                    if dependency in removed_data_dependencies:
                        break
            for removed_data_dependency in removed_data_dependencies:
                resource_m.remove_dependency(removed_data_dependency)

        # Recursively invalidate component results based on other components that were invalidated
        handled_dependencies: Set[ResourceAttributeDependency] = set()

        await self._invalidate_dependencies(
            handled_dependencies,
            unhandled_dependencies,
        )

    def create_component_dependencies(
        self,
        component_id: bytes,
        component_version: int,
    ):
        """
        Register dependencies between the component and the resources it interacts with.

        This may not even be necessary since Resource.add_attributes does this anyway...
        """
        self._validate_resource_context_complete()

        for resource_id in self._component_context.resources_created:
            new_resource_m = self._resource_context.resource_models[resource_id]
            for attributes in new_resource_m.attributes.keys():
                new_resource_m.add_component_for_attributes(
                    component_id, component_version, attributes
                )

    def create_resource_dependencies(
        self,
        component_id: bytes,
    ):
        """
        Register dependencies between a resource with some attributes and the resources which
        were accessed in the context where these attributes were added.

        When a component runs, this method is called to record what data was accessed by the
        component and what resource attributes from other resources were accessed within that
        component. These registered dependencies allow for OFRAK to not rerun analyzers when the
        resource and its dependencies have not changed.

        Whenever a [Modifier][ofrak.component.modifier.Modifier] is run, these resource attribute
        dependencies are invalidated so as to force analysis to be rerun.

        :param bytes component_id:
        """
        self._validate_resource_context_complete()
        resource_dependencies = []

        # Create dependency for each attribute on newly created resources
        for resource_id in self._component_context.resources_created:
            new_resource_m = self._resource_context.resource_models[resource_id]
            for attributes in new_resource_m.attributes.keys():
                resource_dependencies.append(
                    ResourceAttributeDependency(
                        resource_id,
                        component_id,
                        attributes,
                    )
                )

        # Create dependency for each new attribute on modified resources
        for resource_id in self._component_context.modification_trackers.keys():
            modified_resource_m = self._resource_context.resource_models[resource_id]
            for attrs_added in modified_resource_m.diff.attributes_added.keys():
                resource_dependencies.append(
                    ResourceAttributeDependency(
                        resource_id,
                        component_id,
                        attrs_added,
                    )
                )

        # Add dependencies to all resources which were accessed
        for resource_id, access_tracker in self._component_context.access_trackers.items():
            if resource_id in self._component_context.resources_created:
                # Avoid all the newly created components depending on each other
                continue
            accessed_resource_m = self._resource_context.resource_models[resource_id]
            merged_accessed_ranges = Range.merge_ranges(access_tracker.data_accessed)
            # Add attributes dependency on all accessed attributes
            for attributes_accessed in access_tracker.attributes_accessed:
                for resource_dependency in resource_dependencies:
                    accessed_resource_m.add_attribute_dependency(
                        attributes_accessed, resource_dependency
                    )
            # Add data dependency on all accessed data
            for accessed_range in merged_accessed_ranges:
                for resource_dependency in resource_dependencies:
                    accessed_resource_m.add_data_dependency(resource_dependency, accessed_range)

    def _validate_resource_context_complete(self):
        for resource_id in self._component_context.resources_created:
            if resource_id not in self._resource_context.resource_models:
                raise ValueError(
                    f"The resource model {resource_id.hex()} was created but it's not in the "
                    f"resource context"
                )

    async def _fetch_missing_resources(self, resource_ids: Iterable[bytes]):
        missing_resource_ids = set()
        # Fetch all the resources referred to by the unhandled dependencies
        for resource_id in resource_ids:
            if resource_id not in self._resource_context.resource_models:
                missing_resource_ids.add(resource_id)
        missing_resources = await self._resource_service.get_by_ids(missing_resource_ids)
        for missing_resource in missing_resources:
            self._resource_context.resource_models[
                missing_resource.id
            ] = MutableResourceModel.from_model(missing_resource)

    async def _invalidate_dependencies(
        self,
        handled_dependencies: Set[ResourceAttributeDependency],
        unhandled_dependencies: Set[ResourceAttributeDependency],
    ):
        """
        Invalidate the unhandled resource attribute dependencies.

        :param Set[ResourceAttributeDependency] handled_dependencies: A set of dependencies that
        have already been invalidated
        :param Set[ResourceAttributeDependency] unhandled_dependencies: A set of dependencies
        that should be invalidated
        """
        if len(unhandled_dependencies) == 0:
            return

        dependent_resource_ids = {
            dependency.dependent_resource_id for dependency in unhandled_dependencies
        }

        deleted_dependent_ids = {
            r_id
            for r_id, currently_exists in zip(
                dependent_resource_ids,
                await self._resource_service.verify_ids_exist(dependent_resource_ids),
            )
            if not currently_exists
        }
        await self._fetch_missing_resources(
            dependent_resource_ids.difference(deleted_dependent_ids)
        )

        # Invalidate the resources' attributes referred to by the unhandled_dependencies
        next_unhandled_dependencies = set()
        for dependency in unhandled_dependencies:
            # It's possible that the attribute was already invalidated from an earlier run
            if dependency in handled_dependencies:
                continue

            # If the dependent resource was deleted, don't need to propagate dependency invalidation
            if dependency.dependent_resource_id in deleted_dependent_ids:
                handled_dependencies.add(dependency)
                continue

            resource_m = self._resource_context.resource_models[dependency.dependent_resource_id]

            # Invalidate the attributes on the resource
            handled_dependencies.add(dependency)

            # The component id is not necessarily present. It could have been invalidated already
            # by a previous patch that impacted other resources that this resource depends on.
            if resource_m.get_component_id_by_attributes(dependency.attributes):
                resource_m.remove_component(dependency.component_id, dependency.attributes)
                self._component_context.mark_resource_modified(resource_m.id)

            # Find other dependencies to invalidate due to the invalidation of the attributes
            invalidated_dependencies = set()
            for next_dependency in resource_m.attribute_dependencies[dependency.attributes]:
                # Make sure the dependency wasn't already handled
                if next_dependency not in handled_dependencies:
                    LOGGER.debug(
                        f"Invalidating attributes {next_dependency.attributes.__name__} from "
                        f"component {next_dependency.component_id!r} on resource "
                        f"{next_dependency.dependent_resource_id.hex()} due to "
                        f"attributes {dependency.attributes.__name__} on resource"
                        f" {dependency.dependent_resource_id.hex()} being invalidated"
                    )

                    invalidated_dependencies.add(next_dependency)

            for invalidated_dependency in invalidated_dependencies:
                resource_m.remove_dependency(invalidated_dependency)
                self._component_context.mark_resource_modified(resource_m.id)
            next_unhandled_dependencies.update(invalidated_dependencies)

        await self._invalidate_dependencies(
            handled_dependencies,
            next_unhandled_dependencies,
        )


class DependencyHandlerFactory:
    def create(
        self,
        resource_service: ResourceServiceInterface,
        data_service: DataServiceInterface,
        component_context: ComponentContext,
        resource_context: ResourceContext,
    ) -> DependencyHandler:
        return DependencyHandler(
            resource_service, data_service, component_context, resource_context
        )
