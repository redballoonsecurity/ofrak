import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, MutableMapping, Optional, Sequence, Set, Tuple, Type

from ofrak.model.data_model import DataModel, DataPatch
from ofrak.model.resource_model import (
    MutableResourceModel,
    ResourceAttributeDependency,
    ResourceAttributes,
    Data,
)
from ofrak.model.tag_model import ResourceTag
from ofrak.model.viewable_tag_model import ViewableResourceTag, ResourceViewInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type import Range, InvalidStateError

LOGGER = logging.getLogger(__file__)


@dataclass
class ComponentResourceModificationTracker2:
    data_patches: List[DataPatch] = field(default_factory=list)
    tags_added: Set[ResourceTag] = field(default_factory=set)


ViewByTag = MutableMapping[ViewableResourceTag, ResourceViewInterface]


class ResourceTracker:
    def __init__(self, model: MutableResourceModel):
        self.model: MutableResourceModel = model
        self.attribute_reads: Set[Type[ResourceAttributes]] = set()
        self.data_reads: Set[Range] = set()
        self.data_writes: List[Tuple[Range, bytes]] = list()

    def model_modified(self) -> bool:
        return self.model.diff.modified()

    def data_modified(self) -> bool:
        return len(self.data_writes) > 0

    def modified(self) -> bool:
        return self.model_modified() or self.data_modified()


@dataclass
class OFRAKContext2:
    """
    Purpose: Interface between local state and "database" (service state)

    Import functions:
    1. Cache and update resource models appropriately
    2. Cache and update resource views appropriately
    3. Track modifications
        - NOT Tags added - but will need to work out what tags were added when flushing
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

        # TODO: Maybe it would make sense to use ResourceModels as keys to a WeakKeyDictionary, so we forget about the views once there is no reference to them
        # Only problem with that brilliant plan is the circular reference created by Key[Model] -> View -> Resource -> Model
        # However that can be solved by excluding the underlying Resource from cached views, easily
        self.cached_resource_views: MutableMapping[bytes, ViewByTag] = defaultdict(dict)
        self.trackers: MutableMapping[bytes, ResourceTracker] = dict()

        # TODO: You know, it is weird that creation is always "instant" and deletion isn't...
        self.resources_created: Set[bytes] = field(default_factory=set)
        self.resources_to_delete: Set[bytes] = field(default_factory=set)

        # TODO: What data structure?
        # self.history: List[ResourceRecord] = list()

    async def get_model(self, resource_id: bytes) -> MutableResourceModel:
        (tracker,) = await self.get_trackers(resource_id)
        return tracker.model

    async def get_models(self, resource_ids: Sequence[bytes]) -> Sequence[MutableResourceModel]:
        return [tracker.model for tracker in await self.get_trackers(resource_ids)]

    async def get_trackers(self, resource_ids: Sequence[bytes]) -> Sequence[ResourceTracker]:
        missing_ids = [
            resource_id for resource_id in resource_ids if resource_id not in self.trackers
        ]
        if missing_ids:
            models = await self.resource_service.get_by_ids(missing_ids)

            for model in models:
                self.trackers[model.id] = ResourceTracker(MutableResourceModel.from_model(model))

        return [self.trackers[resource_id] for resource_id in resource_ids]

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

    async def _push_deletions(self):
        """
        Handle deletions... somehow

        Q: self.resources_to_delete is a record of already-deleted resources, or a queue of resources to delete?
        So far as it's used, it's a queue, but it seems very useful to have a record
        A: Store the running total of resources deleted separately, in the self._records probably,
            using the return values of this function. I think that resolves that.

        :return: deleted Resource IDs, deleted data model IDs
        """
        deleted_descendants = await self.resource_service.delete_resources(self.resources_to_delete)
        all_deleted_resources: Set[bytes] = set(self.resources_to_delete)
        data_ids_to_delete = []
        for deleted_m in deleted_descendants:
            if deleted_m.id in self.trackers:
                deleted_tracker = self.trackers.pop(deleted_m.id)
            if deleted_m.data_id:
                data_ids_to_delete.append(deleted_m.data_id)
            all_deleted_resources.add(deleted_m.id)

        await self.data_service.delete_models(data_ids_to_delete)

        self.resources_to_delete.clear()

        # TODO: Views??

        return all_deleted_resources, data_ids_to_delete

    async def _push_data_modifications(self):
        # Collect all the queued data patches
        data_patches = []
        for tracker in self.trackers.values():
            for patch_range, patch_contents in tracker.data_writes:
                data_patches.append(
                    DataPatch(
                        patch_range,
                        tracker.model.data_id,
                        patch_contents,
                    )
                )
            tracker.data_writes.clear()

        # Apply patches in data service
        patch_results = await self.data_service.apply_patches(data_patches)

        # Map each patched data ID to tracker and data model
        patched_data_ids = {result.data_id for result in patch_results}
        data_models_by_data_id: Dict[bytes, DataModel] = {
            data_id: data_m
            for data_id, data_m in zip(
                patched_data_ids,
            )
        }
        trackers_by_data_id: Dict[bytes, Tuple[ResourceTracker, DataModel]] = {
            data_id: (tracker, data_m)
            for data_id, tracker, data_m in zip(
                patched_data_ids,
                await self.get_trackers(
                    [
                        model.id
                        # TODO: A little more efficient to not fetch data IDs already in trackers
                        for model in await self.resource_service.get_by_data_ids(patched_data_ids)
                    ]
                ),
                await self.data_service.get_by_ids(patched_data_ids),
            )
        }

        # Go through and update all models' Data
        for data_patch_result in patch_results:
            tracker, data_m = trackers_by_data_id[data_patch_result.data_id]
            tracker.model.add_attributes(Data(data_m.range.start, data_m.range.length()))

        # Then handle post-patch dependencies
        await self.handle_post_patch_dependencies(
            [
                (
                    trackers_by_data_id[specific_model_patches.data_id][0].model,
                    specific_model_patches.patches,
                )
                for specific_model_patches in patch_results
            ]
        )

    async def _push_model_modifications(self):
        # TODO: Flush data and attribute reads down to dependencies in model here?
        """
        Consequence:

        a.get_data()
        a.save()
        a.add_attributes(X)

        Because the data read was already flushed away, no dependency is created for X

        Now this could be desirable and useful sometimes... but, it would be nice to have as a separate function
            _flush_accesses_into_dependencies
        :return:
        """

        diffs = []
        updated_ids = []
        for tracker in self.trackers.values():
            resource_m = tracker.model
            diffs.append(resource_m.save())
            updated_ids.append(resource_m.id)

        await self.resource_service.update_many(diffs)

    async def _flush_accesses_into_dependencies(self):
        """
        Take all the tracked data_reads and attribute_reads, plus attributes_added, and
        synthesize the appropriate dependencies. After completing, all data_reads and data_writes
        are cleared, and resource models have new dependencies as appropriate.

        OFRAK Dependency Tracking:
        When a component adds attributes to a resource, OFRAK also records how other Resources were
        accessed in the component. This allows OFRAK to track that the modified resources
        'depend on' the accessed resources, and appropriately update the modified resources if the
        accessed resource is later changed.

        OFRAK tracks only two specific types of dependencies:
        1. Resource A's attributes X 'depend on' an attribute Y of resources B. Resource A's
        attributes X will be invalidated when resource B's attributes Y changes.
        2. Resource A's attributes X 'depend on' a range (Y,Z) of resource B's data. Resource A's
        attributes X will be invalidated when resource B's has a data patch overlapping with (Y,Z)
        applied to it.

        Attributes being invalidated simply means that when requested through a `Resource.analyze`
        or `Resource.view_as`, an Analyzer will be run to refresh the attributes, even if the
        attributes already exist.

        TODO: Validate the below and what it is saying??
        Whenever a [Modifier][ofrak.component.modifier.Modifier] is run, these resource attribute
        dependencies are invalidated so as to force analysis to be rerun.

        All of this is facilitated by storing data structures on the dependant resources about
        which other resources depend on them and how. To use the terminology of the examples above,
        resource B stores the information that resource A's attributes X depend on its
        (resource B's) attributes Y, or data range (Y,Z), or even both.

        TODO: Note that tracked attributes_added are NOT cleared. THIS FUNCTION CAN ONLY BE CALLED WHEN NO MORE DATA/ATTRIBUTES CAN BE ACCESSED
        Consequence: Attributes added earlier would be marked as dependencies of data/attributes accessed later. CLEARLY WRONG BEHAVIOR.
        THEREFORE, EITHER THIS CAN ONLY BE CALLED WHEN NO MORE DATA/ATTRIBUTES CAN BE ACCESSED, OR WE NEED TO TRACK MODIFICATIONS FOR DEPENDENCY TRACKING SEPARATELY FROM GENERAL TRACKING OF CHANGES
        Solution? New data structure obviously and strictly for dependency tracking
        Dictionary indexed by ... does it matter what it's indexed by?
        We want to keep track of previously accessed stuff so that when there is an attributes added, we can also add dependencies to the accessed stuff
        self._dependencies: Dict[ResourceID, Tuple[ResourceAttributeDependency, Union[Range, Type[ResourceAttributes]]]}
        A record of "dependency events" could also work well

        :return: None
        """

        all_data_reads: List[Tuple[bytes, Range]] = []
        all_attribute_reads: List[Tuple[bytes, Type[ResourceAttributes]]] = []
        all_added_attributes: List[ResourceAttributeDependency] = []
        for tracker in self.trackers.values():
            # Collect the accessed data of this Resource
            all_data_reads.extend(
                (tracker.model.id, read_range) for read_range in tracker.data_reads
            )
            tracker.data_reads.clear()

            # Collect the accessed attributes of this Resource
            all_attribute_reads.extend(
                (tracker.model.id, read_attrs) for read_attrs in tracker.attribute_reads
            )
            tracker.attribute_reads.clear()

            # Collect each dependency for any new attributes of this Resource
            all_added_attributes.extend(
                ResourceAttributeDependency(
                    tracker.model.id,
                    self.current_component_id,
                    attrs_added,
                )
                for attrs_added in tracker.model.diff.attributes_added
            )

        # Mark all the resources that were accessed in order to create each new attributes
        for dependency in all_added_attributes:
            # Mark read_resource_id that there is a dependency on its data contained in read_range
            for read_resource_id, read_range in all_data_reads:
                tracker = self.trackers.get(read_resource_id)
                if not tracker:
                    raise InvalidStateError(
                        f"Tracker for ID {read_resource_id.hex()} disappeared between when all "
                        f"data reads were collected and when attempting to actually add dependency!"
                    )
                tracker.model.add_data_dependency(
                    dependency,
                    read_range,
                )
            # Mark read_resource_id that there is a dependency on its attributes read_attributes
            for read_resource_id, read_attributes in all_attribute_reads:
                tracker = self.trackers.get(read_resource_id)
                if not tracker:
                    raise InvalidStateError(
                        f"Tracker for ID {read_resource_id.hex()} disappeared between when all "
                        f"data reads were collected and when attempting to actually add dependency!"
                    )
                tracker.model.add_attribute_dependency(
                    read_attributes,
                    dependency,
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
        raise NotImplementedError()

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
        raise NotImplementedError()

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

    ###########################################
    # DEPENDENCY HANDLER
    ###########################################

    async def handle_post_patch_dependencies(
        self, patched_models: List[Tuple[MutableResourceModel, List[Range]]]
    ):
        unhandled_dependencies: Set[ResourceAttributeDependency] = set()
        # Figure out which components results must be invalidated based on data changes

        for resource_m, patched_ranges in patched_models:
            removed_data_dependencies = set()
            # Iterate over the resource's data dependencies to find one that's affected by one of
            # the patch range
            for dependency, dependency_ranges in resource_m.data_dependencies.items():
                # Iterate over the resource's data dependency ranges to find a range that overlaps
                # the patch range
                for dependency_range in dependency_ranges:
                    for patch_range in patched_ranges:
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

    def _create_component_dependencies(self):
        """
        Register dependencies between the component and the resources it interacts with.

        This will REPLACE what Resource.add_attributes currently does. In order to do that, this
        needs to be called when flushing - either final flush or intermediate flush
        """
        for tracker in self.trackers.values():
            for attrs_added in tracker.model.diff.attributes_added.keys():
                tracker.model.add_component_for_attributes(
                    self.current_component_id, self.current_component_version, attrs_added
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
                resource_m = self.cached_resource_models[dependency.dependent_resource_id]
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
