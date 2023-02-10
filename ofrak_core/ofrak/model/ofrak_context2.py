import functools
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Set, MutableMapping, List, Optional, Iterable, cast
from weakref import WeakValueDictionary

from ofrak.model.component_model import (
    ComponentResourceAccessTracker,
    ComponentResourceModificationTracker,
    ComponentRunResult,
)
from ofrak.model.data_model import DataPatch, DataPatchesResult
from ofrak.model.resource_model import MutableResourceModel, ResourceAttributeDependency
from ofrak.model.tag_model import ResourceTag
from ofrak.model.viewable_tag_model import ViewableResourceTag, ResourceViewInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type import Range

LOGGER = logging.getLogger(__file__)


@dataclass
class ComponentResourceModificationTracker2:
    data_patches: List[DataPatch] = field(default_factory=list)
    tags_added: Set[ResourceTag] = field(default_factory=set)


ViewByTag = MutableMapping[ViewableResourceTag, ResourceViewInterface]


@dataclass
class OFRAKContext2:
    """
    Purpose: Interface between local state and "database" (service state)

    Import functions:
    1. Cache and update resource models appropriately
    2. Cache and update resource views appropriately
    3. Track modifications
        - Tags added
        - Data patches
        - Any modification (is_modified)
           Currently the root "truth" for this lives in ResourceModel.is_modified
    4. Track accesses
        - Data ranges accessed
        - Attributes accessed


    MutableResourceModel will have an instance of this guy
    when anything gets modified, it updates the trackers?

    Push before running component, pull after
    Push after component or context ends

    I need to figure out the hierarchy of which information goes where

    ## Base, client context
      |
      V
    ## Call Component 1
      Resource.run
        JobService.run
          AbstractComponent.run
            Component1.{unpack,analyze,modify,identify,pack}
          Component needs to know what global state to modify. PUSH TO GLOBAL STATE
          Component needs to know what was modified so that it can mark dependencies it created
        JobService needs tags added (well only if its auto-run, but generally speaking)
      Resource needs to know how to update its own cache - what was modified? PULL FROM GLOBAL STATE
      |
      V
    ## Call Component 2

    """

    def __init__(
        self,
        resource_service: ResourceServiceInterface,
        data_service: DataServiceInterface,
        component_id: bytes,
        component_version: int,
    ):
        self.resource_service = resource_service
        self.data_service = data_service
        self.current_component_id: bytes = component_id
        self.current_component_version: int = component_version

        self.resource_models: MutableMapping[bytes, MutableResourceModel] = WeakValueDictionary()
        self.views_by_resource: MutableMapping[bytes, ViewByTag] = defaultdict(WeakValueDictionary)

        self.access_trackers: Dict[bytes, ComponentResourceAccessTracker] = field(
            default_factory=lambda: defaultdict(ComponentResourceAccessTracker)
        )
        self.modification_trackers: Dict[bytes, ComponentResourceModificationTracker] = field(
            default_factory=lambda: defaultdict(ComponentResourceModificationTracker)
        )
        self.resources_created: Set[bytes] = field(default_factory=set)
        self.resources_deleted: Set[bytes] = field(default_factory=set)

        self.history: List[ComponentRunResult] = list()

    def mark_resource_modified(self, r_id: bytes):
        # Creates a new tracker if none exists, and leaves tracker untouched if it already exists
        _ = self.modification_trackers[r_id]

    def get_modified_resource_ids(self, include_deleted=False) -> Set[bytes]:
        modified_resource_ids = set(self.modification_trackers.keys())
        if not include_deleted:
            modified_resource_ids = modified_resource_ids.difference(self.resources_deleted)
        return modified_resource_ids

    def fork(
        self,
        component_id: Optional[bytes] = None,
        component_version: Optional[int] = None,
    ) -> "OFRAKContext2":
        return OFRAKContext2(
            self.resource_service,
            self.data_service,
            component_id if component_id else self.current_component_id,
            component_version if component_version else self.current_component_version,
        )

    async def push(self):
        """
        Push pending changes to global state


        1. Handle deleted resources
        2. Handle deleted data models (as a result of 1)
        3. Handle data patches
        4. Handle dependencies
        5. Push updated resource models
        :return:
        """

    async def pull(self):
        """
        Pull from global state to update local state
        How do we know what state to update? This will need to take a list or something of resource
        models or IDs (IDs are better)
        Then the result of a component run (or whatever) can be pulled into here.

        1. Pull resource models
        2. Update resource views
        :return:
        """

    async def finish_context(self):
        """
        Called when exiting a context
        For example, when component finishes

        May not be necessary, we can just always call push

        But if we want to strictly only handle dependencies at the end, can do dependency handling
        here.

        :return:
        """
        await self.push()

    async def flush(self) -> ComponentRunResult:
        resources_to_delete: Set[bytes] = self.resources_deleted
        resources_to_update: Set[bytes] = set(self.modification_trackers.keys())

        data_ids_to_delete = []
        for deleted_r_m in await self.resource_service.delete_resources(resources_to_delete):
            resources_to_update.discard(deleted_r_m.id)
            if deleted_r_m.data_id is not None:
                data_ids_to_delete.append(deleted_r_m.data_id)

        patches_to_apply: List[DataPatch] = list()
        for modified_r_id in resources_to_update:
            modification_tracker = self.modification_trackers.get(modified_r_id)
            assert modification_tracker is not None, (
                f"Resource {modified_r_id} was " f"marked as modified but is missing a tracker!"
            )
            patches_to_apply.extend(modification_tracker.data_patches)

            modification_tracker.data_patches.clear()

        await self.data_service.delete_models(data_ids_to_delete)
        patch_results = await self.data_service.apply_patches(patches_to_apply)

        await self.handle_post_patch_dependencies(patch_results)

        diffs = []
        updated_ids = []
        for resource_id in resources_to_update:
            resource_m = self.resource_models
            diffs.append(resource_m.save())
            updated_ids.append(resource_m.id)
        await self.resource_service.update_many(diffs)
        self.update_views(updated_ids, resources_to_delete)

    ###########################################
    # DEPENDENCY HANDLER
    ###########################################
    @functools.lru_cache(None)
    async def map_data_ids_to_resources(
        self, data_ids: Iterable[bytes]
    ) -> Dict[bytes, MutableResourceModel]:
        resources_by_data_id = dict()
        for resource_id, resource_m in self.resource_models.items():
            if resource_m.data_id is not None:
                resources_by_data_id[resource_m.data_id] = resource_m

        missing_data_ids = set()
        for data_id in data_ids:
            if data_id not in resources_by_data_id:
                missing_data_ids.add(data_id)

        missing_resources = await self.resource_service.get_by_data_ids(missing_data_ids)
        for missing_resource in missing_resources:
            missing_resource_data_id = cast(bytes, missing_resource.data_id)
            if missing_resource_data_id in resources_by_data_id:
                raise ValueError("Something is wrong in the implementation")
            mutable_resource = MutableResourceModel.from_model(missing_resource)
            resources_by_data_id[missing_resource_data_id] = mutable_resource
            self.resource_models[missing_resource.id] = mutable_resource

        return resources_by_data_id

    async def handle_post_patch_dependencies(self, patch_results: List[DataPatchesResult]):
        # Create look up maps for resources and dependencies
        resources_by_data_id = await self.map_data_ids_to_resources(
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
                    for patch_range in data_patch_result.patches:
                        if not dependency_range.overlaps(patch_range):
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

        for resource_id in self.resources_created:
            new_resource_m = self.resource_models[resource_id]
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
        for resource_id in self.resources_created:
            new_resource_m = self.resource_models[resource_id]
            for attributes in new_resource_m.attributes.keys():
                resource_dependencies.append(
                    ResourceAttributeDependency(
                        resource_id,
                        component_id,
                        attributes,
                    )
                )

        # Create dependency for each new attribute on modified resources
        for resource_id in self.modification_trackers.keys():
            modified_resource_m = self.resource_models[resource_id]
            for attrs_added in modified_resource_m.diff.attributes_added.keys():
                resource_dependencies.append(
                    ResourceAttributeDependency(
                        resource_id,
                        component_id,
                        attrs_added,
                    )
                )

        # Add dependencies to all resources which were accessed
        for resource_id, access_tracker in self.access_trackers.items():
            if resource_id in self.resources_created:
                # Avoid all the newly created components depending on each other
                continue
            accessed_resource_m = self.resource_models[resource_id]
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
        for resource_id in self.resources_created:
            if resource_id not in self.resource_models:
                raise ValueError(
                    f"The resource model {resource_id.hex()} was created but it's not in the "
                    f"resource context"
                )

    async def _fetch_missing_resources(self, resource_ids: Iterable[bytes]):
        missing_resource_ids = set()
        # Fetch all the resources referred to by the unhandled dependencies
        for resource_id in resource_ids:
            if resource_id not in self.resource_models:
                missing_resource_ids.add(resource_id)
        missing_resources = await self.get_by_ids(missing_resource_ids)
        for missing_resource in missing_resources:
            self.resource_models[missing_resource.id] = MutableResourceModel.from_model(
                missing_resource
            )

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
                await self.verify_ids_exist(dependent_resource_ids),
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

            try:
                resource_m = self.resource_models[dependency.dependent_resource_id]
            except KeyError as e:
                missing_model = await self.get_by_id(dependency.dependent_resource_id)
                resource_m = MutableResourceModel.from_model(missing_model)

            # Invalidate the attributes on the resource
            handled_dependencies.add(dependency)

            # The component id is not necessarily present. It could have been invalidated already
            # by a previous patch that impacted other resources that this resource depends on.
            if resource_m.get_component_id_by_attributes(dependency.attributes):
                resource_m.remove_component(dependency.component_id, dependency.attributes)
                self.mark_resource_modified(resource_m.id)

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
                self.mark_resource_modified(resource_m.id)
            next_unhandled_dependencies.update(invalidated_dependencies)

        await self._invalidate_dependencies(
            handled_dependencies,
            next_unhandled_dependencies,
        )
