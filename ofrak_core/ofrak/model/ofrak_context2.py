import asyncio
import logging
import os
from dataclasses import fields
from typing import (
    Dict,
    List,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    Iterable,
    cast,
    TypeVar,
)

from ofrak import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, File
from ofrak.model.component_model import (
    ComponentRunResult,
    CLIENT_COMPONENT_ID,
    CLIENT_COMPONENT_VERSION,
)
from ofrak.model.data_model import DataModel, DataPatch
from ofrak.model.ofrak_context_interface import OFRAKContext2Interface, ResourceTracker
from ofrak.model.resource_model import (
    MutableResourceModel,
    ResourceAttributeDependency,
    ResourceAttributes,
    Data,
    ResourceModel,
)
from ofrak.model.tag_model import ResourceTag
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.id_service_i import IDServiceInterface
from ofrak.service.job_service_i import JobServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type import Range, InvalidStateError

LOGGER = logging.getLogger(__file__)


S = TypeVar("S", bound=AbstractOfrakService)


class OFRAKContext2(OFRAKContext2Interface):
    """
    Purpose: Interface between local state and "database" (service state)

    Important functions:
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
        job_id: bytes = b"root",
        component_id: bytes = CLIENT_COMPONENT_ID,
        component_version: int = CLIENT_COMPONENT_VERSION,
        services: List[AbstractOfrakService] = [],
    ):
        self.services: Dict[Type[S], S] = self._set_up_services_dict(services)

        self.job_id: bytes = job_id  # This could be unique to each context?
        self.current_component_id: bytes = component_id
        self.current_component_version: int = component_version

        self.trackers: MutableMapping[bytes, ResourceTracker] = dict()

        self.resources_to_delete: Set[bytes] = set()

        # TODO: Do we need this? BTW, it is weird that creation is always "instant" and deletion isn't...
        self.resources_created: Set[bytes] = set()

        self.history: List[ComponentRunResult] = []

        # TODO: Also include component locator? Unpacker at least needs it

    @property
    def resource_service(self) -> ResourceServiceInterface:
        return self.services[ResourceServiceInterface]

    @property
    def data_service(self) -> DataServiceInterface:
        return self.services[DataServiceInterface]

    @property
    def id_service(self) -> IDServiceInterface:
        return self.services[IDServiceInterface]

    async def get_resources(self, *resource_ids: bytes) -> Iterable[Resource]:
        trackers = await self._get_trackers(resource_ids)
        resources = [Resource(self, tracker) for tracker in trackers]
        return resources

    def fork(
        self,
        job_id: Optional[bytes] = None,
        component_id: Optional[bytes] = None,
        component_version: Optional[int] = None,
    ) -> "OFRAKContext2":
        new_context = OFRAKContext2(
            job_id if job_id is not None else self.job_id,
            component_id if component_id is not None else self.current_component_id,
            component_version if component_version is not None else self.current_component_version,
            [],
        )

        new_context.services = self.services
        return new_context

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
        deleted_ids, deleted_data_ids = await self._push_deletions()
        self._update_deleted_resource(deleted_ids)
        patched_model_ranges = await self._push_data_modifications()
        await self._flush_dependencies(patched_model_ranges)
        resource_models_modified, tags_added = await self._push_model_modifications()
        data_models_modified = {model.id for model, _ in patched_model_ranges}

        self.history.append(
            ComponentRunResult(
                {
                    self.current_component_id,
                },
                resources_modified=resource_models_modified.union(data_models_modified),
                resources_deleted=set(deleted_data_ids),
                resources_created=set(self.resources_created),
                tags_added=tags_added,
            )
        )
        self.resources_created.clear()

    async def pull(
        self,
        modified_resource_ids: Iterable[bytes],
        deleted_resource_ids: Iterable[bytes],
    ):
        """
        Pull from global state to update local state
        How do we know what state to update? This will need to take a list or something of resource
        models or IDs (IDs are better)
        Then the result of a component run (or whatever) can be pulled into here.

        1. Pull resource models
        2. Update resource views
        :return:
        """
        await self._pull_models(modified_resource_ids)
        self._update_deleted_resource(deleted_resource_ids)

        self._update_modified_views(modified_resource_ids)

    def get_cumulative_result(self) -> ComponentRunResult:
        result = ComponentRunResult()
        for intermediate_result in self.history:
            result.update(intermediate_result)

        return result

    async def create_root_resource(
        self, name: str, data: bytes, tags: Iterable[ResourceTag] = (GenericBinary,)
    ) -> Resource:
        job_id = self.id_service.generate_id()
        resource_id = self.id_service.generate_id()
        data_id = resource_id

        await self.services[JobServiceInterface].create_job(job_id, name)
        await self.data_service.create_root(data_id, data)
        resource_model = await self.resource_service.create(
            ResourceModel.create(resource_id, data_id, tags=tags)
        )
        (root_resource,) = await self.get_resources(resource_id)
        return root_resource

    async def create_root_resource_from_file(self, file_path: str) -> Resource:
        full_file_path = os.path.abspath(file_path)
        with open(full_file_path, "rb") as f:
            root_resource = await self.create_root_resource(
                os.path.basename(full_file_path), f.read(), (File,)
            )
        root_resource.add_view(
            File(
                os.path.basename(full_file_path),
                os.lstat(full_file_path),
                FilesystemRoot._get_xattr_map(full_file_path),
            )
        )
        await root_resource.save()
        return root_resource

    async def start_context(self):
        if "_ofrak_context" in globals():
            raise InvalidStateError(
                "Cannot start OFRAK context as a context has already been started in this process!"
            )
        globals()["_ofrak_context"] = self
        await asyncio.gather(*(service.run() for service in self.services.values()))

    async def shutdown_context(self):
        if "_ofrak_context" in globals():
            del globals()["_ofrak_context"]
        await asyncio.gather(*(service.shutdown() for service in self.services.values()))
        logging.shutdown()

    ## Private helper methods only beyond this point

    async def _get_model(self, resource_id: bytes) -> MutableResourceModel:
        (tracker,) = await self._get_trackers((resource_id,))
        return tracker.model

    async def _get_models(self, resource_ids: Sequence[bytes]) -> Sequence[MutableResourceModel]:
        return [tracker.model for tracker in await self._get_trackers(resource_ids)]

    def _set_up_services_dict(self, all_services: List[AbstractOfrakService]) -> Dict[Type[S], S]:
        d = dict()
        for service in all_services:
            service_i: Optional[Type[AbstractOfrakService]] = None
            for base_class in type(service).mro():
                if AbstractOfrakService in base_class.__bases__:
                    service_i = base_class  # type: ignore
                    break
            if service_i is not None:
                d[service_i] = service
            else:
                LOGGER.warning(
                    f"{service} was passed as an OFRAK service to context initialization, but "
                    f"could not find the base class inheriting from AbstractOfrakService! "
                    f"Ignoring..."
                )

        return d

    async def _get_trackers(
        self, resource_ids: Sequence[bytes], resources_must_exist: bool = True
    ) -> Sequence[ResourceTracker]:
        missing_ids = [
            resource_id for resource_id in resource_ids if resource_id not in self.trackers
        ]
        if missing_ids:
            if resources_must_exist:
                models = await self.resource_service.get_by_ids(missing_ids)
            else:
                resources_exist = zip(
                    missing_ids, await self.resource_service.verify_ids_exist(missing_ids)
                )
                models = await self.resource_service.get_by_ids(
                    r_id for r_id, r_exists in resources_exist if r_exists
                )

            for model in models:
                self.trackers[model.id] = ResourceTracker(MutableResourceModel.from_model(model))

        return [self.trackers[resource_id] for resource_id in resource_ids]

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
            if deleted_m.data_id:
                data_ids_to_delete.append(deleted_m.data_id)
            all_deleted_resources.add(deleted_m.id)

        await self.data_service.delete_models(data_ids_to_delete)

        self.resources_to_delete.clear()

        return all_deleted_resources, data_ids_to_delete

    async def _push_data_modifications(self) -> List[Tuple[MutableResourceModel, List[Range]]]:
        """
        Apply queued data patches to resources via data service, returning the affected resources.
        Resources' special Data attributes are also updated.

        :return: List of resources modified by patches, alongside which ranges were modified
        """
        # Collect all the queued data patches
        data_patches = []
        for tracker in self.trackers.values():
            for patch_range, patch_contents in tracker.data_writes:
                data_patches.append(
                    DataPatch(
                        patch_range,
                        cast(bytes, tracker.model.data_id),
                        patch_contents,
                    )
                )
            tracker.data_writes.clear()

        # Apply patches in data service
        patch_results = await self.data_service.apply_patches(data_patches)

        # Map each patched data ID to tracker and data model
        patched_data_ids = {result.data_id for result in patch_results}
        trackers_by_data_id: Dict[bytes, Tuple[ResourceTracker, DataModel]] = {
            data_id: (tracker, data_m)
            for data_id, tracker, data_m in zip(
                patched_data_ids,
                await self._get_trackers(
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

        return [
            (
                trackers_by_data_id[specific_model_patches.data_id][0].model,
                specific_model_patches.patches,
            )
            for specific_model_patches in patch_results
        ]

    async def _push_model_modifications(self) -> Tuple[Set[bytes], Dict[bytes, Set[ResourceTag]]]:
        """
        Save changes to the model in remote.

        Does NOT update dependencies. See _flush_dependencies for that.

        :return: Set of all IDs whose models were modified
        """

        diffs = []
        updated_ids = set()
        tags_added = dict()
        for tracker in self.trackers.values():
            if tracker.model_modified() and not tracker.is_deleted:
                resource_m = tracker.model
                diff = resource_m.save()
                diffs.append(diff)
                updated_ids.add(resource_m.id)
                if diff.tags_added:
                    tags_added[resource_m.id] = diff.tags_added

        await self.resource_service.update_many(diffs)
        return updated_ids, tags_added

    async def _pull_models(self, modified_resource_ids: Iterable[bytes]):
        """
        Update local cached resource models
        :return:
        """

        models_to_fetch = set()
        for modified_resource_id in modified_resource_ids:
            if modified_resource_id not in self.trackers:
                continue

            current_tracker = self.trackers[modified_resource_id]
            if current_tracker.is_dirty():
                raise InvalidStateError(
                    f"Cannot pull resource {modified_resource_id.hex()} because the local version "
                    f"has unpushed changes: {current_tracker.why_dirty()}"
                )

            models_to_fetch.add(modified_resource_id)

        for r_id, updated_model in zip(
            models_to_fetch, await self.resource_service.get_by_ids(models_to_fetch)
        ):
            tracker = self.trackers[r_id]
            tracker.model = MutableResourceModel.from_model(updated_model)

    def _update_deleted_resource(self, deleted_ids: Iterable[bytes]):
        for deleted_id in deleted_ids:
            if deleted_id in self.trackers:
                deleted_tracker = self.trackers[deleted_id]

                if deleted_tracker.is_deleted:
                    # Already marked as deleted. Weird it happened twice, but benign?
                    continue
                if deleted_tracker.is_dirty():
                    raise InvalidStateError(
                        f"Cannot pull resource {deleted_id.hex()} because it would be deleted but "
                        f"the local version has unpushed changes: {deleted_tracker.why_dirty()}"
                    )

                deleted_tracker.is_deleted = True
                for view in deleted_tracker.views.values():
                    view.set_deleted()

    def _create_dependencies(self):
        """
        Create dependencies linking the creation of pending attributes-added and previously
        accessed data and attributes. These dependencies are added to the models of the resources
        which were read.

        This method is idempotent, that is, calling it multiple times without pushing the
        modified models (and therefore clearing the set of attributes-added) will result in
        duplicated work, but will not result in duplicate dependencies in the accessed resource's
        models.

        :return:
        """
        # Collect all the attributes added
        all_added_attributes: List[ResourceAttributeDependency] = [
            ResourceAttributeDependency(
                tracker.model.id,
                self.current_component_id,
                attrs_added,
            )
            for tracker in self.trackers.values()
            for attrs_added in tracker.model.diff.attributes_added
        ]

        # Collect all the data read
        all_data_reads: List[Tuple[bytes, Range]] = [
            (tracker.model.id, read_range)
            for tracker in self.trackers.values()
            for read_range in tracker.data_reads
        ]
        # Collect all the attributes read
        all_attribute_reads: List[Tuple[bytes, Type[ResourceAttributes]]] = [
            (tracker.model.id, read_attrs)
            for tracker in self.trackers.values()
            for read_attrs in tracker.attribute_reads
        ]

        # The record of data reads and attribute reads is NOT cleared, so that creating new
        # attributes after calling .push() will still add the dependencies for those new attributes
        # data and attributes read previously

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

    async def _apply_dependency_invalidations(self):
        """
        As attributes are modified, the attributes (possibly of other resources) which depended on
        those are queued to be marked as invalid. This method applies those invalidations to the
        dependent resources, fetching them if they are not already tracked, so that trying to
        analyze those attributes in the future will trigger re-analysis.
        """
        unhandled_dependencies = set()
        for tracker in self.trackers.values():
            unhandled_dependencies.update(tracker.model.diff.data_dependencies_removed)
            unhandled_dependencies.update(tracker.model.diff.attribute_dependencies_removed)

        # Invalidate attributes of all resources that depend on modified attributes or data
        await self._invalidate_dependencies_recursively(
            set(),
            unhandled_dependencies,
        )

    async def _flush_dependencies(
        self, patched_model_ranges: List[Tuple[MutableResourceModel, List[Range]]]
    ):
        """
        Take all the tracked data_reads and attribute_reads, plus attributes_added, and
        synthesize the appropriate dependencies. After completing, all data_reads and data_writes
        are cleared, and resource models have new dependencies as appropriate.

        Note that **neither tracked attributes_added nor the attributes_reads and data_reads are
        cleared.** This means that calling it multiple times will result in more and more
        dependencies being added, since every attribute is assumed to depend on every

        This function should only be called
        right before pushing the context state and therefore clearing the attributes read. Otherwise, attributes added earlier would be marked
        as dependencies of data/attributes accessed later.

        :return: None
        """

        self._queue_dependencies_to_invalidate(patched_model_ranges)
        self._create_dependencies()
        self._create_component_dependencies()
        await self._apply_dependency_invalidations()

    def _queue_dependencies_to_invalidate(
        self, patched_models: List[Tuple[MutableResourceModel, List[Range]]]
    ):
        """
        Given a number of resource models and the patched ranges of each model, invalidate any
        attributes of other resources that depend on that patched data.

        :param patched_models:
        :return:
        """
        # Figure out which components' results must be invalidated based on data changes
        for resource_m, patched_ranges in patched_models:
            removed_data_dependencies = set()
            # Iterate over the resource's data dependencies to find one that's affected by one of
            # the patch range
            for dependency, dependency_ranges in resource_m.data_dependencies.items():
                # Iterate over the resource's data dependency ranges to find a range that overlaps
                # the patch range
                ranges_overlapping = (
                    dependency_range.overlaps(patch_range)
                    for dependency_range in dependency_ranges
                    for patch_range in patched_ranges
                )
                if any(ranges_overlapping):
                    LOGGER.debug(
                        f"Invalidating results of {dependency.component_id!r} on resource "
                        f"{dependency.dependent_resource_id.hex()} due to a data change on "
                        f"resource {resource_m.id.hex()}"
                    )
                    removed_data_dependencies.add(dependency)
            for removed_data_dependency in removed_data_dependencies:
                resource_m.remove_dependency(removed_data_dependency)

        # Figure out which components' results must be invalidated based on attribute changes
        # Check each resource with modified attributes for dependencies on those attributes
        for tracker in self.trackers.values():
            model = tracker.model
            attributes_modified = model.diff.attributes_removed.union(
                model.diff.attributes_added.keys()
            )
            # Remove any dependencies on modified attributes
            for attributes_type_altered in attributes_modified:
                dependencies = model.attribute_dependencies.get(attributes_type_altered, ())
                for dependency in dependencies:
                    model.remove_dependency(dependency)

    def _create_component_dependencies(self):
        """
        Register dependencies between the component and the resources it interacts with.

        TODO This will REPLACE what Resource.add_attributes currently does.
        """
        for tracker in self.trackers.values():
            for attrs_added in tracker.model.diff.attributes_added.keys():
                tracker.model.add_component_for_attributes(
                    self.current_component_id, self.current_component_version, attrs_added
                )

    async def _invalidate_dependencies_recursively(
        self,
        handled_dependencies: Set[ResourceAttributeDependency],
        unhandled_dependencies: Set[ResourceAttributeDependency],
    ):
        """
        Invalidate attributes of all resources that depend on modified attributes or data. This is
        done recursively, breadth-first: If attributes X depend on attributes Y and attributes Y
        gets invalidated, then attributes X will also get invalidated.

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

        _ = await self._get_trackers(list(dependent_resource_ids), resources_must_exist=False)

        # Invalidate the resources' attributes referred to by the unhandled_dependencies
        next_unhandled_dependencies = set()
        for dependency in unhandled_dependencies:
            # It's possible that the attribute was already invalidated from an earlier run
            if dependency in handled_dependencies:
                continue

            tracker = self.trackers.get(dependency.dependent_resource_id)
            if tracker is None or tracker.is_deleted:
                # If the dependent resource was deleted, don't need to propagate dependency invalidation
                # TODO: Allowing locally but not globally deleted resources is new, think it through
                handled_dependencies.add(dependency)
                continue
            resource_m = tracker.model

            # Invalidate the attributes on the resource
            handled_dependencies.add(dependency)

            # The component id is not necessarily present. It could have been invalidated already
            # by a previous patch that impacted other resources that this resource depends on.
            if resource_m.get_component_id_by_attributes(dependency.attributes):
                resource_m.remove_component(dependency.component_id, dependency.attributes)

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
            next_unhandled_dependencies.update(invalidated_dependencies)

        await self._invalidate_dependencies_recursively(
            handled_dependencies,
            next_unhandled_dependencies,
        )

    def _update_modified_views(self, modified: Iterable[bytes]):
        """
        Synchronize cached views with the resource model, presumably after it has been updated

        :param modified:
        :return:
        """
        for resource_id in modified:
            if resource_id not in self.trackers:
                continue

            tracker = self.trackers[resource_id]
            views_in_context = tracker.views
            for view in views_in_context.values():
                updated_model = tracker.model
                fresh_view = view.create(updated_model)
                for _field in fields(fresh_view):
                    if _field.name == "_resource":
                        continue
                    setattr(view, _field.name, getattr(fresh_view, _field.name))
