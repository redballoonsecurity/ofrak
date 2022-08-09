import asyncio
import dataclasses
import hashlib
import logging
from typing import BinaryIO, Iterable, List, Optional, Tuple, Type, TypeVar, cast, Union

from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import ComponentContext, CC, ComponentRunResult
from ofrak.model.data_model import DataPatch, DataMove
from ofrak.model.job_model import (
    JobRunContext,
)
from ofrak.model.job_request_model import (
    JobAnalyzerRequest,
    JobComponentRequest,
    JobMultiComponentRequest,
)
from ofrak.model.resource_model import (
    ResourceAttributes,
    ResourceModel,
    MutableResourceModel,
    ResourceContext,
)
from ofrak.model.tag_model import ResourceTag
from ofrak.model.viewable_tag_model import (
    ViewableResourceTag,
    ResourceViewInterface,
    ResourceViewContext,
)
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.dependency_handler import DependencyHandler
from ofrak.service.id_service_i import IDServiceInterface
from ofrak.service.job_service_i import JobServiceInterface
from ofrak.service.resource_service_i import (
    ResourceServiceInterface,
    ResourceFilter,
    ResourceSort,
)
from ofrak_type.error import NotFoundError, InvalidStateError
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)
RT = TypeVar("RT", bound="ResourceTag")
RA = TypeVar("RA", bound="ResourceAttributes")
RV = TypeVar("RV", bound="ResourceViewInterface")


class Resource:
    """
    Defines methods for interacting with the data and attributes of Resources, the main building
    block of OFRAK.
    """

    __slots__ = (
        "_job_id",
        "_job_context",
        "_component_context",
        "_resource_context",
        "_resource_view_context",
        "_resource",
        "_resource_factory",
        "_id_service",
        "_resource_service",
        "_data_service",
        "_job_service",
        "_dependency_handler",
    )

    def __init__(
        self,
        job_id: bytes,
        resource: MutableResourceModel,
        resource_context: ResourceContext,
        resource_view_context: ResourceViewContext,
        job_context: Optional[JobRunContext],
        component_context: ComponentContext,
        resource_factory: "ResourceFactory",
        id_service: IDServiceInterface,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        job_service: JobServiceInterface,
    ):
        self._job_id: bytes = job_id
        self._job_context: Optional[JobRunContext] = job_context
        self._component_context: ComponentContext = component_context
        self._resource_context: ResourceContext = resource_context
        self._resource_view_context: ResourceViewContext = resource_view_context
        self._resource: MutableResourceModel = resource

        self._resource_factory: "ResourceFactory" = resource_factory
        self._id_service: IDServiceInterface = id_service
        self._resource_service: ResourceServiceInterface = resource_service
        self._data_service: DataServiceInterface = data_service
        self._job_service: JobServiceInterface = job_service

        self._dependency_handler = DependencyHandler(
            self._resource_service,
            self._data_service,
            self._component_context,
            self._resource_context,
        )

    def get_id(self) -> bytes:
        """
        :return: This resource's ID
        """
        return self._resource.id

    def get_job_id(self) -> bytes:
        """
        Each resource belongs to a specific "job." See
        [JobServiceInterface][ofrak.service.job_service_i.JobServiceInterface].

        :return: The ID of the job this resource belongs to
        """
        return self._job_id

    def get_data_id(self) -> Optional[bytes]:
        """
        Each resource may have a data ID. This refers to a
        [DataModel][ofrak.model.data_model.DataModel] representing some chunk of raw binary data.

        :return: The data ID associated with this resource, if it exists
        """
        return self._resource.data_id

    def get_resource_context(self) -> ResourceContext:
        return self._resource_context

    def get_resource_view_context(self) -> ResourceViewContext:
        return self._resource_view_context

    def get_component_context(self) -> ComponentContext:
        return self._component_context

    def get_job_context(self) -> Optional[JobRunContext]:
        return self._job_context

    def get_caption(self) -> str:
        return self._resource.caption

    def is_modified(self) -> bool:
        """
        Check if the resource has been modified in this context and is considered "dirty".
        :return: `True` if the resource is modified, `False` otherwise
        """
        return self._resource.is_modified

    def get_model(self) -> MutableResourceModel:
        """
        Get the underlying [model][ofrak.model.resource_model.ResourceModel] of this resource.
        :return:
        """
        return self._resource

    async def get_data(self, range: Optional[Range] = None) -> bytes:
        """
        A resource often represents a chunk of underlying binary data. This method returns the
        entire chunk by default; this can be reduced by an optional parameter.

        :param range: A range within the resource's data, relative to the resource's data itself
        (e.g. Range(0, 10) returns the first 10 bytes of the chunk)

        :return: The full range or a partial range of this resource's bytes
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot get data from a resource with no data"
            )
        data = await self._data_service.get_data(self._resource.data_id, range)
        if range is None:
            range = Range(0, len(data))
        self._component_context.access_trackers[self._resource.id].data_accessed.add(range)
        return data

    async def get_data_length(self) -> int:
        """
        :return: The length of the underlying binary data this resource represents
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot get data length from a "
                "resource with no data."
            )
        return await self._data_service.get_data_length(self._resource.data_id)

    async def get_data_index_within_parent(self) -> int:
        """
        Data is stored as a tree structure. Each data ID corresponds to a node; nodes's children
        are sorted by offset. The index of a node in their parent's list of children indicates
        the relative ordering of the child resources which correspond to those child nodes.

        :return: The relative position of this resource's data node in the parent
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot get data index from a "
                "resource with no data."
            )
        return await self._data_service.get_index_within_parent(self._resource.data_id)

    async def get_data_range_within_parent(self) -> Range:
        """
        If this resource is "mapped," i.e. its underlying data is defined as a range of its parent's
        underlying data, this method returns the range within the parent resource's data where this
        resource lies. If this resource is not mapped (it is root), it returns a range starting at 0
        with length equal to the length of this resource's data.

        :return: The range of the parent's data which this resource represents
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot get data range from a "
                "resource with no data."
            )
        return await self._data_service.get_range_within_parent(self._resource.data_id)

    async def get_data_range_within_root(self) -> Range:
        """
        Does the same thing as `get_data_range_within_parent`, except the range is relative to the
        root.

        :return: The range of the root node's data which this resource represents
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot get data range from a "
                "resource with no data."
            )
        return await self._data_service.get_data_range_within_root(self._resource.data_id)

    async def get_offset_within_root(self) -> int:
        """
        Does the same thing as `get_data_range_within_root`, except it returns the start offset of
        the relative range to the root.

        :return: The start offset of the root node's data which this resource represents
        """
        root_range = await self.get_data_range_within_root()
        return root_range.start

    async def get_data_unmapped_range(self, offset: int) -> Range:
        """
        This resource may have children mapped in at particular ranges of this resource's
        underlying binary data. This method gets a range starting at an ``offset`` and ending at
        the start of the next range mapped by a child.

        :param offset: An offset from the start of this resource's binary data where the unmapped
        range should start

        :raises OutOfBoundError: If the provided offset is not a valid offset within the resource
        :raises AmbiguousOrderError: If there is unmapped data directly before the given offset

        :return: A range starting at ``offset`` and ending at the the offset of the start of the
        next range mapped by a child or, if the ``offset`` is within a mapped range,
        ending at ``offset`` to create a 0-length range
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot get data range from a "
                "resource with no data."
            )
        return await self._data_service.get_unmapped_range(self._resource.data_id, offset)

    async def set_data_alignment(self, alignment: int):
        """
        Set the alignment constraint for the data node associated with this resource. This method
        does not modify the resource's data, but sets an alignment value that can be used to
        ensure that unpackers and modifiers do not make changes that violate the set alignment.

        :param alignment: The new alignment value
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot set data alignment for a "
                "resource with no data."
            )
        return await self._data_service.set_alignment(self._resource.data_id, alignment)

    async def set_data_overlaps_enabled(self, enable_overlaps: bool):
        """
        Enable or disable allowing overlaps for the data node associated with this resource. If
        enabled, mapped children can overlap each other. If disabled, attempting to map a child
        which overlaps another will raise an error.

        :param enable_overlaps: Whether or not data overlaps are enabled
        """
        if self._resource.data_id is None:
            raise ValueError(
                "Resource does not have a data_id. Cannot enable data overlaps for a "
                "resource with no data."
            )
        return await self._data_service.set_overlaps_enabled(
            self._resource.data_id, enable_overlaps
        )

    async def save(self):
        """
        If this resource has been modified, update the model stored in the resource service with
        the local changes.

        :raises NotFoundError: If the resource service does not have a model for this resource's ID
        """
        if self._resource.is_deleted:
            await self._resource_service.delete_resource(self._resource.id)
            await self._data_service.delete_tree(self._resource.data_id)
        elif self._resource.is_modified:
            modification_tracker = self._component_context.modification_trackers.get(
                self._resource.id
            )
            assert modification_tracker is not None, (
                f"Resource {self._resource.id.hex()} was "
                f"marked as modified but is missing a tracker!"
            )
            patch_results = await self._data_service.apply_patches(
                modification_tracker.data_patches, modification_tracker.data_moves
            )
            modification_tracker.data_patches.clear()
            modification_tracker.data_moves.clear()
            await self._dependency_handler.handle_post_patch_dependencies(patch_results)
            await self._resource_service.update(self._resource.save())
        else:
            return

    async def _fetch(self, resource: MutableResourceModel):
        if resource.is_modified and not resource.is_deleted:
            raise InvalidStateError(
                f"Cannot fetch dirty resource {resource.id.hex()} (resource "
                f"{self.get_id().hex()} attempted fetch)"
            )
        try:
            fetched_resource = await self._resource_service.get_by_id(resource.id)
        except NotFoundError:
            del self._resource_context.resource_models[resource.id]
            return

        resource.reset(fetched_resource)

    async def _fetch_resources(self, resource_ids: Iterable[bytes]):
        tasks = []
        for resource_id in resource_ids:
            context_resource = self._resource_context.resource_models.get(resource_id)
            if context_resource is not None:
                tasks.append(self._fetch(context_resource))
        await asyncio.gather(*tasks)

    async def _update_views(self, component_result: ComponentRunResult):
        for resource_id in component_result.resources_modified:
            views_in_context = self._resource_view_context.views_by_resource[resource_id]
            for view in views_in_context.values():
                updated_model = self._resource_context.resource_models[resource_id]
                fresh_view = view.create(updated_model)
                for field in dataclasses.fields(fresh_view):
                    if field.name == "_resource":
                        continue
                    setattr(view, field.name, getattr(fresh_view, field.name))

        for resource_id in component_result.resources_deleted:
            views_in_context = self._resource_view_context.views_by_resource[resource_id]
            for view in views_in_context.values():
                view.set_deleted()

    async def fetch(self):
        """
        Update the local model with the latest version from the resource service. This will fail
        if this resource has been modified.

        :raises InvalidStateError: If the local resource model has been modified
        :raises NotFoundError: If the resource service does not have a model for this resource's ID
        """
        return await self._fetch(self._resource)

    async def run(
        self,
        component_type: Type[ComponentInterface[CC]],
        config: CC = None,
    ) -> ComponentRunResult:
        """
        Run a single component. Runs even if the component has already been run on this resource.

        :param component_type: The component type (may be an interface) to get and run
        :param config: Optional config to pass to the component

        :return: A ComponentRunResult containing information on resources affected by the component
        """
        job_context = self._job_context
        component_result = await self._job_service.run_component(
            JobComponentRequest(
                self._job_id,
                self._resource.id,
                component_type.get_id(),
                config,
            ),
            job_context,
        )
        await self._fetch_resources(component_result.resources_modified)
        await self._update_views(component_result)
        return component_result

    async def auto_run(
        self,
        components: Iterable[Type[ComponentInterface]] = tuple(),
        blacklisted_components: Iterable[Type[ComponentInterface]] = tuple(),
        all_unpackers: bool = False,
        all_identifiers: bool = False,
        all_analyzers: bool = False,
        all_packers: bool = False,
    ) -> ComponentRunResult:
        """
        Automatically run multiple components which may run on this resource. From an initial set
        of possible components to run, this set is searched for components for which the
        intersection of the component's targets and this resource's tags is not empty. Accepts
        several optional flags to expand or restrict the initial set of components.

        :param components: Components to explicitly add to the initial set of components
        :param blacklisted_components: Components to explicitly remove to the initial set of
        components
        :param all_unpackers: If true, all Unpackers are added to the initial set of components
        :param all_identifiers: If true, all Identifiers are added to the initial set of components
        :param all_analyzers: If true, all Analyzers are added to the initial set of components

        :return: A ComponentRunResult containing information on resources affected by the component
        """
        components_result = await self._job_service.run_components(
            JobMultiComponentRequest(
                self._job_id,
                self._resource.id,
                components_allowed=tuple(c.get_id() for c in components),
                components_disallowed=tuple(c.get_id() for c in blacklisted_components),
                all_unpackers=all_unpackers,
                all_identifiers=all_identifiers,
                all_analyzers=all_analyzers,
                all_packers=all_packers,
            )
        )
        await self._fetch_resources(components_result.resources_modified)
        await self._update_views(components_result)
        return components_result

    async def unpack(self) -> ComponentRunResult:
        """
        Unpack the resource.

        :return: A ComponentRunResult containing information on resources affected by the component
        """
        return await self.auto_run(all_identifiers=True, all_unpackers=True)

    async def analyze(self, resource_attributes: Type[RA]) -> RA:
        """
        Analyze the resource for a specific resource attribute.

        :param Type[RA] resource_attributes:

        :return:
        """
        await self.analyze_attributes(resource_attributes)
        attributes = self.get_attributes(resource_attributes)
        return attributes

    async def identify(self):
        """
        Run all registered identifiers on the resource, tagging it with matching resource tags.
        """
        await self.auto_run(all_identifiers=True)

    async def pack(self) -> ComponentRunResult:
        """
        Pack the resource.

        :return: A ComponentRunResult containing information on resources affected by the component
        """
        return await self.auto_run(all_packers=True)

    async def auto_run_recursively(
        self,
        components: Iterable[Type[ComponentInterface]] = tuple(),
        blacklisted_components: Iterable[Type[ComponentInterface]] = tuple(),
        blacklisted_tags: Iterable[ResourceTag] = tuple(),
        all_unpackers: bool = False,
        all_identifiers: bool = False,
        all_analyzers: bool = False,
    ) -> ComponentRunResult:
        """
        Automatically run multiple components which may run on this resource or its descendents.
        From an initial set of possible components to run, this set is searched for components
        for which the intersection of the component's targets and this resource's tags is not
        empty. Accepts several optional flags to expand or restrict the initial set of
        components.
        After each run, compatible components from the initial set are run on any resources which
        have had tags added (including newly created resources). This is repeated until no new
        tags are added.

        :param components: Components to explicitly add to the initial set of components
        :param blacklisted_components: Components to explicitly remove to the initial set of
        components
        :param all_unpackers: If true, all Unpackers are added to the initial set of components
        :param all_identifiers: If true, all Identifiers are added to the initial set of components
        :param all_analyzers: If true, all Analyzers are added to the initial set of components

        :return: A ComponentRunResult containing information on resources affected by the component
        """
        components_result = await self._job_service.run_components_recursively(
            JobMultiComponentRequest(
                self._job_id,
                self._resource.id,
                components_allowed=tuple(c.get_id() for c in components),
                components_disallowed=tuple(c.get_id() for c in blacklisted_components),
                all_unpackers=all_unpackers,
                all_identifiers=all_identifiers,
                all_analyzers=all_analyzers,
                tags_ignored=tuple(blacklisted_tags),
            )
        )
        await self._fetch_resources(components_result.resources_modified)
        await self._update_views(components_result)
        return components_result

    async def unpack_recursively(
        self,
        blacklisted_components: Iterable[Type[ComponentInterface]] = tuple(),
        do_not_unpack: Iterable[ResourceTag] = tuple(),
    ) -> ComponentRunResult:
        """
        Automatically unpack this resource and recursively unpack all of its descendants. First
        this resource is unpacked; then, any resource which "valid" tags were added to will also be
        unpacked. New resources created with tags count as resources with new tags. A "valid" tag
        is a tag which is not explicitly ignored via the ``do_not_unpack`` argument.
        The unpacking will only stop when no new "valid" tags have been added in the previous
        iteration. This can lead to a very long unpacking process if it is totally unconstrained.

        :param blacklisted_components: Components which are blocked from running during the
        recursive unpacking, on this resource or any descendants.
        :param do_not_unpack: Do not unpack resources with this tag, and ignore these tags when
        checking if any new tags have been added in this iteration.

        :return: A ComponentRunResult containing information on resources affected by the component
        """
        return await self.auto_run_recursively(
            all_identifiers=True,
            all_unpackers=True,
            blacklisted_components=blacklisted_components,
            blacklisted_tags=do_not_unpack,
        )

    async def analyze_recursively(self) -> ComponentRunResult:
        return await self.auto_run_recursively(all_analyzers=True)

    async def pack_recursively(self) -> ComponentRunResult:
        """
        Recursively pack the resource, starting with its descendants.
        """
        return await self._job_service.pack_recursively(self._job_id, self._resource.id)

    async def write_to(self, destination: BinaryIO):
        """
        Recursively repack resource and write data out to an arbitrary ``BinaryIO`` destination.
        :param destination: Destination for packed resource data
        :return:
        """
        await self.pack_recursively()
        destination.write(await self.get_data())

    async def _analyze_attributes(self, attribute_type: Type[ResourceAttributes]):
        job_context = self._job_context
        components_result = await self._job_service.run_analyzer_by_attribute(
            JobAnalyzerRequest(
                self._job_id,
                self._resource.id,
                attribute_type,
                tuple(self._resource.tags),
            ),
            job_context,
        )
        # Update all the resources in the local context that were modified as part of the
        # analysis
        await self._fetch_resources(components_result.resources_modified)
        await self._update_views(components_result)
        return components_result

    async def _create_resource(self, resource_model: ResourceModel) -> "Resource":
        return await self._resource_factory.create(
            self._job_id,
            resource_model.id,
            self._resource_context,
            self._resource_view_context,
            self._component_context,
            self._job_context,
        )

    async def _create_resources(
        self, resource_models: Iterable[ResourceModel]
    ) -> Iterable["Resource"]:
        return await self._resource_factory.create_many(
            self._job_id,
            [resource_model.id for resource_model in resource_models],
            self._resource_context,
            self._resource_view_context,
            self._component_context,
            self._job_context,
        )

    async def create_child(
        self,
        tags: Iterable[ResourceTag] = None,
        attributes: Iterable[ResourceAttributes] = None,
        data: Optional[bytes] = None,
        data_range: Optional[Range] = None,
        data_after: Optional["Resource"] = None,
        data_before: Optional["Resource"] = None,
    ) -> "Resource":
        """
        Create a new resource as a child of this resource. This method entirely defines the
        child's tags and attributes. This method also defines the child's data semantics:

        A child resource can either be defined in one of three ways:
        1) The resource contains no data ("Dataless" resource). Not used in practice.
        2) As mapping a range of its parent's data ("Mapped" resource). For example, an instruction
        maps a portion of its parent basic block.
        3) Defining its own new, independent data ("Unmapped" resource). For example,
        a file extracted from a zip archive is a child of the zip archive resource, but its data
        does not map to some specific range of that parent archive.

        By default a resource will be defined the third way (unmapped). To specify that the
        resource is a mapped resource, include the optional ``data_range`` parameter set to the
        range of the parent's data which the child maps. That is, `data_range=Range(0,
        10)` creates a resource which maps the first 10 bytes of the parent.
        The optional ``data`` param defines whether to populate the new child's data. It can be used
        whether the resource is mapped or unmapped. If the child is mapped, the value of
        ``data`` is applied as a patch to the mapped child; because it is mapped, those bytes are
        also patched into the parent resource. If the child is unmapped, the value of ``data``
        still becomes that child's data, but the parent's data is unaffected. If ``data`` and
        ``data_range`` are both `None` (default), the new child is a dataless resource.

        The following table sums up the possible interactions between ``data`` and ``data_range``:

        |                          | ``data_range`` param not `None`                        | ``data_range`` param `None`                  |
        |--------------------------|--------------------------------------------------------|----------------------------------------------|
        | ``data`` param not `None` | Child mapped, ``data`` patched into child (and parent) | Child unmapped, child's data set to ``data`` |
        | ``data`` param   `None`   | Child mapped, parent's data untouched                  | Child is dataless                            |

        There are two additional data-centric parameters: ``data_after`` and ``data_before``.
        These can only be used in combination with ``data_range``; zero, one, or both of them may
        be used. These are useful in special cases when 1) the parent resource allows data
        overlaps and 2) the new child already has some sibling resources who also map the parent's
        data and overlap with the new child's data. These parameters hint to the data service what
        order the children's data is
        arranged, which may be useful in the future when patching the resource. For example,
        if 3 resources A, B, and C are all created with `data_range=Range(2,2)`, and later each of
        them are individually patched, the data service needs these hints to know whether the
        children's data should be mapped into the parent's data as `aaabbbccc`, `aaacccbbb`,
        `bbbaaaccc`, etc.
        This should not happen often.

        :param tags: [tags][ofrak.model.tag_model.ResourceTag] to add to the new child
        :param attributes: [attributes][ofrak.model.resource_model.ResourceAttributes] to add to
        the new child
        :param data: The binary data for the new child. If `None` and ``data_range`` is `None`,
        the resource has no data. Defaults to `None`.
        :param data_range: The range of the parent's data which the new child maps. If `None` (
        default), the child will not map the parent's data.
        :param data_after: The sibling resource whose data is sequentially after the new resource
        :param data_before: The sibling resource whose data is sequentially before the new resource
        :return:
        """
        data_model_id: Optional[bytes]
        if data_range is not None:
            if self._resource.data_id is None:
                raise ValueError(
                    "Cannot create a child with mapped data from a parent that doesn't have data"
                )
            data_model_id = self._id_service.generate_id()
            await self._data_service.create_mapped(
                data_model_id,
                self._resource.data_id,
                data_range,
                after_data_id=data_after.get_data_id() if data_after is not None else None,
                before_data_id=data_before.get_data_id() if data_before is not None else None,
            )
        elif data is not None:
            if self._resource.data_id is None:
                raise ValueError(
                    "Cannot create a child with data from a parent that doesn't have data"
                )
            if data_after is not None or data_before is not None:
                raise ValueError(
                    "The data_after/data_before parameters should only be provided when creating "
                    "a child with mapped data from this resource."
                )
            data_model_id = self._id_service.generate_id()
            await self._data_service.create(data_model_id, data)
        else:
            data_model_id = None
        resource_id = self._id_service.generate_id()
        resource_model = ResourceModel.create(
            resource_id,
            data_model_id,
            self._resource.id,
            tags,
            attributes,
            self._component_context.component_id,
            self._component_context.component_version,
        )
        await self._resource_service.create(resource_model)
        if self._job_context:
            resource_tracker = self._job_context.trackers[resource_model.id]
            resource_tracker.tags_added.update(resource_model.tags)
        self._component_context.mark_resource_modified(resource_id)
        self._component_context.resources_created.add(resource_model.id)
        created_resource = await self._create_resource(resource_model)
        if data_range is not None and data is not None:
            # Patch the resource with the provided data
            created_resource.queue_patch(Range.from_size(0, data_range.length()), data)
        return created_resource

    async def create_child_from_view(
        self,
        view: RV,
        data_range: Optional[Range] = None,
        data: Optional[bytes] = None,
        additional_tags: Iterable[ResourceTag] = (),
        additional_attributes: Iterable[ResourceAttributes] = (),
    ) -> "Resource":
        """
        Create a new resource as a child of this resource. The new resource will have tags and
        attributes as defined by the [view][ofrak.model.viewable_tag_model.ViewableResourceTag];
        in this way a view can act as a template to create a new resource.

        The ``additional_tags`` and ``additional_attributes`` can also be used to add more tags
        and attributes beyond what the view contains.

        This method's ``data`` and ``data_range`` parameters have the same semantics as in
        `create_child`, in short:

        |                          | ``data_range`` param not `None`                        | ``data_range`` param `None`                  |
        |--------------------------|--------------------------------------------------------|----------------------------------------------|
        | ``data`` param not `None` | Child mapped, ``data`` patched into child (and parent) | Child unmapped, child's data set to ``data`` |
        | ``data`` param   `None`   | Child mapped, parent's data untouched                  | Child is dataless                            |

        See `create_child` documentation for details.

        :param view: A [resource view][ofrak.resource_view] to pull
        [tags][ofrak.model.tag_model.ResourceTag] and
        [attributes][ofrak.model.resource_model.ResourceAttributes] from to populate the new child
        :param data_range: The range of the parent's data which the new child maps. If `None` (
        default), the child will not map the parent's data.
        :param data: The binary data for the new child. If `None` and ``data_range`` is `None`,
        the resource has no data. Defaults to `None`.
        :param additional_tags: Any [tags][ofrak.model.tag_model.ResourceTag] for the child in
        addition to those from the ``view``
        :param additional_attributes: Any
        [attributes][ofrak.model.resource_model.ResourceAttributes] for the child in addition to
        those from the ``view``
        :return:
        """
        viewable_tag: ViewableResourceTag = type(view)
        new_resource = await self.create_child(
            tags=(viewable_tag, *additional_tags),
            attributes=(*view.get_attributes_instances().values(), *additional_attributes),
            data_range=data_range,
            data=data,
        )
        return new_resource

    async def view_as(self, viewable_tag: Type[RV]) -> RV:
        """
        Provides a specific type of view instance for this resource. The returned instance is an
        object which has some of the information from this same resource, however in a simpler
        interface. This resource instance will itself remain available through the view's
        ``.resource`` property.
        :param viewable_tag: A ViewableResourceTag, which this resource's model must already contain

        :raises ValueError: If the model does not contain this tag, or this tag is not a
        ViewableResourceTag

        :return:
        """
        if not self._resource_view_context.has_view(self.get_id(), viewable_tag):
            if not issubclass(viewable_tag, ResourceViewInterface):
                raise ValueError(
                    f"Cannot get view for resource {self.get_id().hex()} of a type "
                    f"{viewable_tag.__name__} because it is not a subclass of ResourceView"
                )
            if not self.has_tag(viewable_tag):
                raise ValueError(
                    f"Cannot get resource {self.get_id().hex()} as view "
                    f"{viewable_tag.__name__} because the resource is not tagged as a "
                    f"{viewable_tag.__name__}"
                )
            composed_attrs_types = viewable_tag.composed_attributes_types
            analysis_tasks = [self.analyze(attrs_t) for attrs_t in composed_attrs_types]
            await asyncio.gather(*analysis_tasks)
            view = viewable_tag.create(self.get_model())
            view.resource = self  # type: ignore
            self._resource_view_context.add_view(self.get_id(), view)
            return cast(RV, view)
        return self._resource_view_context.get_view(self.get_id(), viewable_tag)

    def add_view(self, view: ResourceViewInterface):
        """
        Add all the attributes composed in a view to this resource, and tag this resource with
        the view type. Calling this is the equivalent of making N ``add_attributes`` calls and
        one ``add_tag`` call (where N is the number of attributes the view is composed of).

        :param view: An instance of a view
        """
        attributes: ResourceAttributes
        for attributes in view.get_attributes_instances().values():
            self.add_attributes(attributes)
        self.add_tag(type(view))

    def _set_modified(self):
        self._component_context.mark_resource_modified(self._resource.id)

    def _add_tag(self, tag: ResourceTag):
        """
        Associate a tag with the resource. If the resource already have the provided tag, it has no
        effects. All parent classes of the provided tag that are tags themselves are also added.
        """
        if self._resource.has_tag(tag, False):
            return
        self._component_context.mark_resource_modified(self._resource.id)
        new_tags = self._resource.add_tag(tag)
        if self._job_context:
            resource_tracker = self._job_context.trackers[self._resource.id]
            resource_tracker.tags_added.update(new_tags)

    def add_tag(self, *tags: ResourceTag):
        """
        Associate multiple tags with the resource. If the resource already have one of the provided
        tag, the tag is not added. All parent classes of the provided tag that are tags themselves
        are also added.
        """
        for tag in tags:
            self._add_tag(tag)

    def get_tags(self, inherit: bool = True) -> Iterable[ResourceTag]:
        """
        Get a set of tags associated with the resource.
        """
        return self._resource.get_tags(inherit)

    def get_related_tags(self, tag: RT) -> List[RT]:
        """
        Get all tags associated with the resource which inherit from the given tag (if any).
        """
        return self._resource.get_specific_tags(tag)

    def has_tag(self, tag: ResourceTag, inherit: bool = True) -> bool:
        """
        Determine if the resource is associated with the provided tag.
        """
        return self._resource.has_tag(tag, inherit)

    def remove_tag(self, tag: ResourceTag):
        if not self._resource.has_tag(tag):
            return
        self._set_modified()
        self._resource.remove_tag(tag)

    def get_most_specific_tags(self) -> Iterable[ResourceTag]:
        """
        Get all tags associated with the resource from which no other tags on that resource
        inherit. In other words, get the resource's tags that aren't subclassed by other tags on
        the resource.

        For example, for a resource tagged as `Elf`, the result would be just `[Elf]` instead of
        `[Elf, Program, GenericBinary]` that `Resource.get_tags` returns. This is because `Elf`
        inherits from `Program`, which inherits from `GenericBinary`. Even though the resource
        has all of those tags, the most derived class with no other derivatives is the "most
        specific."
        """
        return self._resource.get_most_specific_tags()

    async def analyze_attributes(
        self,
        attributes_type: Type[RA],
    ):
        # TODO: Should we be using the version as well? The client wouldn't now the
        #  version of the component in a client-server environment. We could do that efficiently by
        #  adding a service method that list all available components (and their version)
        # Check that the attributes are there to begin with
        attributes = self._resource.get_attributes(attributes_type)
        if attributes is not None:
            # Make sure that the attributes have not been invalidated
            component_id = self._resource.get_component_id_by_attributes(type(attributes))
            if component_id is not None:
                return attributes
        await self._analyze_attributes(attributes_type)

    def _add_attributes(self, attributes: ResourceAttributes):
        existing_attributes = self._resource.get_attributes(type(attributes))
        if existing_attributes is not None and existing_attributes == attributes:
            return
        self._set_modified()
        self._resource.add_attributes(attributes)
        component_context = self._component_context
        self._resource.add_component_for_attributes(
            component_context.component_id, component_context.component_version, type(attributes)
        )

    def add_attributes(self, *attributes: ResourceAttributes):
        """
        Add the provided attributes to the resource. If the resource already have the
        provided attributes classes, they are replaced with the provided one.
        """
        for attrs in attributes:
            self._add_attributes(attrs)

    def has_attributes(self, attributes_type: Type[ResourceAttributes]) -> bool:
        """
        Check if this resource has a value for the given attributes type.
        :param attributes_type:
        :return:
        """
        return self._resource.has_attributes(attributes_type)

    def get_attributes(self, attributes_type: Type[RA]) -> RA:
        """
        If this resource has attributes matching the given type, return the value of those
        attributes. Otherwise returns `None`.
        :param attributes_type:
        :return:
        """
        attributes = self._resource.get_attributes(attributes_type)
        if attributes is None:
            raise NotFoundError(
                f"Cannot find attributes {attributes_type} for resource {self.get_id().hex()}"
            )

        self._component_context.access_trackers[self._resource.id].attributes_accessed.add(
            attributes_type
        )
        return attributes

    def get_all_attributes(self) -> Iterable[ResourceAttributes]:
        """
        Get values for all the attributes this resource has.
        :return:
        """
        return list(self._resource.attributes.values())

    def remove_attributes(self, attributes_type: Type[ResourceAttributes]):
        """
        Remove the value of a given attributes type from this resource, if there is such a value.
        If the resource does not have a value for the given attributes type, do nothing.
        :param attributes_type:
        :return:
        """
        if not self._resource.has_attributes(attributes_type):
            return
        self._set_modified()
        self._resource.remove_attributes(attributes_type)

    def add_component(
        self,
        component_id: bytes,
        version: int,
    ):
        """
        Mark that a component has run on this resource

        :param component_id: ID of the component which ran
        :param version: Version of the component which ran
        :return:
        """
        self._set_modified()
        self._resource.add_component(component_id, version)

    def add_component_for_attributes(
        self,
        component_id: bytes,
        version: int,
        attributes: Type[ResourceAttributes],
    ):
        """
        Mark that a component was responsible for adding some attributes to this resource.
        :param component_id: ID of the component which added the attributes
        :param version: version of the component which added the attributes
        :param attributes: The type of attributes which were added
        :return:
        """
        self._set_modified()
        self._resource.add_component_for_attributes(component_id, version, attributes)

    def remove_component(
        self,
        component_id: bytes,
        attributes: Optional[Type[ResourceAttributes]] = None,
    ):
        """
        Remove any information that this component ran on this resource and/or added a particular
        type of attributes to this resource
        :param component_id: ID of the component to remove information about
        :param attributes: The type of attributes to remove information about
        :return:
        """
        self._set_modified()
        self._resource.remove_component(component_id, attributes)

    def has_component_run(self, component_id: bytes, desired_version: Optional[int] = None) -> bool:
        """
        Check if a particular component has run on this resource

        :param component_id: ID of the component to check for
        :param desired_version: If this is not `None`, also check that a specific version of
        ``component`` ran. Defaults to ``None``.
        :return: `True` if a component matching ``component_id`` and ``desired_version`` ran on
        this resource, `False` otherwise. If ``desired_version`` is `None`, only ``component_id``
        must be matched to return `True`.
        """
        version = self._resource.get_component_version(component_id)
        if version is None:
            return False
        if desired_version is None:
            return True
        return version == desired_version

    def move(
        self,
        range: Range,
        after: Optional["Resource"] = None,
        before: Optional["Resource"] = None,
    ):
        if not self._component_context:
            raise InvalidStateError(
                f"Cannot remap resource {self._resource.id.hex()} outside of a modifier component"
            )
        if self._resource.data_id is None:
            raise ValueError("Cannot create a data move for a resource with no data")
        self._component_context.modification_trackers[self._resource.id].data_moves.append(
            DataMove(
                range,
                self._resource.data_id,
                after_data_id=after.get_data_id() if after is not None else None,
                before_data_id=before.get_data_id() if before is not None else None,
            )
        )

    def queue_patch(
        self,
        patch_range: Range,
        data: bytes,
        after: Optional["Resource"] = None,
        before: Optional["Resource"] = None,
    ):
        """
        Replace the data within the provided range with the provided data. This operation may
        shrink, expand or leave untouched the resource's data. Patches are queued up to be
        applied, and will only be applied to the resource's data after the component this was
        called from exits.

        :param patch_range: The range of binary data in this resource to replace
        :param data: The bytes to replace part of this resource's data with
        :param after: If the patched resource's data overlaps another resources, this hints to the
        data service that the data added by patch should be after the data of resource ``after``
        :param before: If the patched resource's data overlaps another resources, this hints to the
        data service that the data added by patch should be before the data of resource ``before``
        :return:
        """
        if not self._component_context:
            raise InvalidStateError(
                f"Cannot patch resource {self._resource.id.hex()} without a context"
            )
        if self._resource.data_id is None:
            raise ValueError("Cannot patch a resource with no data")
        self._component_context.modification_trackers[self._resource.id].data_patches.append(
            DataPatch(
                patch_range,
                self._resource.data_id,
                data,
                after_data_id=after.get_data_id() if after is not None else None,
                before_data_id=before.get_data_id() if before is not None else None,
            )
        )
        self._resource.is_modified = True

    async def get_parent_as_view(self, v_type: Type[RV]) -> RV:
        """
        Get the parent of this resource. The parent will be returned as an instance of the given
        [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].

        :param v_type: The type of [view][ofrak.resource] to get the parent as
        """
        parent_r = await self.get_parent()
        return await parent_r.view_as(v_type)

    async def get_parent(self) -> "Resource":
        """
        Get the parent of this resource.
        """
        models = list(
            await self._resource_service.get_ancestors_by_id(self._resource.id, max_count=1)
        )
        if len(models) != 1:
            raise NotFoundError(f"There is no parent for resource {self._resource.id.hex()}")
        return await self._create_resource(models[0])

    async def get_ancestors(
        self,
        r_filter: ResourceFilter = None,
    ) -> Iterable["Resource"]:
        """
        Get all the ancestors of this resource. May optionally filter the ancestors so only those
        matching certain parameters are returned.

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If a filter was provided and no resources match the provided filter
        """
        models = await self._resource_service.get_ancestors_by_id(
            self._resource.id, r_filter=r_filter
        )
        return await self._create_resources(models)

    async def get_only_ancestor_as_view(
        self,
        v_type: Type[RV],
        r_filter: ResourceFilter,
    ) -> RV:
        """
        Get the only ancestor of this resource which matches the given filter. The ancestor will be
        returned as an instance of the given
        [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If more or fewer than one ancestor matches ``r_filter``
        """
        ancestor_r = await self.get_only_ancestor(r_filter)
        return await ancestor_r.view_as(v_type)

    async def get_only_ancestor(self, r_filter: ResourceFilter) -> "Resource":
        """
        Get the only ancestor of this resource which matches the given filter.

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:
        """
        ancestors = list(
            await self._resource_service.get_ancestors_by_id(self._resource.id, 1, r_filter)
        )
        if len(ancestors) == 0:
            raise NotFoundError(
                f"There is no ancestor for resource {self._resource.id.hex()} matching the "
                f"provided filter"
            )
        return await self._create_resource(ancestors[0])

    async def get_descendants_as_view(
        self,
        v_type: Type[RV],
        max_depth: int = -1,
        r_filter: ResourceFilter = None,
        r_sort: ResourceSort = None,
    ) -> Iterable[RV]:
        """
        Get all the descendants of this resource. May optionally filter the descendants so only
        those matching certain parameters are returned. May optionally sort the descendants by
        an indexable attribute value key. The descendants will be returned as an
        instance of the given [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].

        :param v_type: The type of [view][ofrak.resource] to get the descendants as
        :param max_depth: Maximum depth from this resource to search for descendants; if -1,
        no maximum depth
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :param r_sort: Specifies which indexable attribute to use as the key to sort and the
        direction to sort
        :return:

        :raises NotFoundError: If a filter was provided and no resources match the provided filter
        """
        descendants = await self.get_descendants(max_depth, r_filter, r_sort)
        view_tasks = [r.view_as(v_type) for r in descendants]
        return await asyncio.gather(*view_tasks)

    async def get_descendants(
        self,
        max_depth: int = -1,
        r_filter: ResourceFilter = None,
        r_sort: ResourceSort = None,
    ) -> Iterable["Resource"]:
        """
        Get all the descendants of this resource. May optionally filter the descendants so only
        those matching certain parameters are returned. May optionally sort the descendants by
        an indexable attribute value key.

        :param max_depth: Maximum depth from this resource to search for descendants; if -1,
        no maximum depth
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :param r_sort: Specifies which indexable attribute to use as the key to sort and the
        direction to sort
        :return:

        :raises NotFoundError: If a filter was provided and no resources match the provided filter
        """
        models = await self._resource_service.get_descendants_by_id(
            self._resource.id, max_depth=max_depth, r_filter=r_filter, r_sort=r_sort
        )
        return await self._create_resources(models)

    async def get_only_descendant_as_view(
        self,
        v_type: Type[RV],
        max_depth: int = -1,
        r_filter: ResourceFilter = None,
    ) -> RV:
        """
        If a filter is provided, get the only descendant of this resource which matches the given
        filter. If a filter is not provided, gets the only descendant of this resource. The
        descendant will be returned as an instance of the given
        [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].

        :param v_type: The type of [view][ofrak.resource] to get the descendant as
        :param max_depth: Maximum depth from this resource to search for descendants; if -1,
        no maximum depth
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If a filter is provided and more or fewer than one descendant matches
        ``r_filter``
        :raises NotFoundError: If a filter is not provided and this resource has multiple descendant
        """
        descendant_r = await self.get_only_descendant(max_depth, r_filter)
        return await descendant_r.view_as(v_type)

    async def get_only_descendant(
        self,
        max_depth: int = -1,
        r_filter: ResourceFilter = None,
    ) -> "Resource":
        """
        If a filter is provided, get the only descendant of this resource which matches the given
        filter. If a filter is not provided, gets the only descendant of this resource.

        :param max_depth: Maximum depth from this resource to search for descendants; if -1,
        no maximum depth
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If a filter is provided and more or fewer than one descendant matches
        ``r_filter``
        :raises NotFoundError: If a filter is not provided and this resource has multiple descendant
        """
        models = list(
            await self._resource_service.get_descendants_by_id(
                self._resource.id,
                max_depth=max_depth,
                max_count=2,
                r_filter=r_filter,
            )
        )
        if len(models) == 0:
            raise NotFoundError(
                f"There is no descendant for resource {self._resource.id.hex()} matching "
                f"the provided filter {r_filter}"
            )
        if len(models) > 1:
            # TODO: Not the right kind of error
            raise NotFoundError(
                f"There are multiple descendants for resource {self._resource.id.hex()} "
                f"matching the provided filter"
            )
        return await self._create_resource(models[0])

    async def get_siblings_as_view(
        self,
        v_type: Type[RV],
        r_filter: ResourceFilter = None,
        r_sort: ResourceSort = None,
    ) -> Iterable[RV]:
        """
        Get all the siblings (resources which share a parent) of this resource. May optionally
        filter the siblings so only those matching certain parameters are returned. May optionally
        sort the siblings by an indexable attribute value key. The siblings
        will be returned as an instance of the given
        [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].

        :param v_type: The type of [view][ofrak.resource] to get the siblings as
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :param r_sort: Specifies which indexable attribute to use as the key to sort and the
        direction to sort
        :return:

        :raises NotFoundError: If a filter was provided and no resources match the provided filter
        """
        siblings = await self.get_siblings(r_filter, r_sort)
        view_tasks = [r.view_as(v_type) for r in siblings]
        return await asyncio.gather(*view_tasks)

    async def get_siblings(
        self,
        r_filter: ResourceFilter = None,
        r_sort: ResourceSort = None,
    ) -> Iterable["Resource"]:
        """
        Get all the siblings (resources which share a parent) of this resource. May optionally
        sort the siblings by an indexable attribute value key. May optionally
        filter the siblings so only those matching certain parameters are returned.

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :param r_sort: Specifies which indexable attribute to use as the key to sort and the
        direction to sort
        :return:

        :raises NotFoundError: If a filter was provided and no resources match the provided filter
        """
        models = await self._resource_service.get_siblings_by_id(
            self._resource.id, r_filter=r_filter, r_sort=r_sort
        )
        return await self._create_resources(models)

    async def get_only_sibling_as_view(
        self,
        v_type: Type[RV],
        r_filter: ResourceFilter = None,
    ) -> RV:
        """
        If a filter is provided, get the only sibling of this resource which matches the given
        filter. If a filter is not provided, gets the only sibling of this resource. The sibling
        will be returned as an instance of the given
        [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].
        :param v_type: The type of [view][ofrak.resource] to get the sibling as
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If a filter is provided and more or fewer than one sibling matches
        ``r_filter``
        :raises NotFoundError: If a filter is not provided and this resource has multiple siblings
        """
        sibling_r = await self.get_only_sibling(r_filter)
        return await sibling_r.view_as(v_type)

    async def get_only_sibling(self, r_filter: ResourceFilter = None) -> "Resource":
        """
        If a filter is provided, get the only sibling of this resource which matches the given
        filter. If a filter is not provided, gets the only sibling of this resource.

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If a filter is provided and more or fewer than one sibling matches
        ``r_filter``
        :raises NotFoundError: If a filter is not provided and this resource has multiple siblings
        """
        models = list(
            await self._resource_service.get_siblings_by_id(
                self._resource.id,
                max_count=2,
                r_filter=r_filter,
            )
        )
        if len(models) == 0:
            raise NotFoundError(
                f"There is no sibling for resource {self._resource.id.hex()} matching "
                f"the provided filter"
            )
        if len(models) > 1:
            raise NotFoundError(
                f"There are multiple siblings for resource {self._resource.id.hex()} "
                f"matching the provided filter"
            )
        return await self._create_resource(models[0])

    async def get_children(
        self,
        r_filter: ResourceFilter = None,
        r_sort: ResourceSort = None,
    ) -> Iterable["Resource"]:
        """
        Get all the children of this resource. May optionally sort the children by an
        indexable attribute value key. May optionally filter the children so only those
        matching certain parameters are returned.

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :param r_sort: Specifies which indexable attribute to use as the key to sort and the
        direction to sort
        :return:

        :raises NotFoundError: If a filter was provided and no resources match the provided filter
        """
        return await self.get_descendants(1, r_filter, r_sort)

    async def get_children_as_view(
        self,
        v_type: Type[RV],
        r_filter: ResourceFilter = None,
        r_sort: ResourceSort = None,
    ) -> Iterable[RV]:
        """
        Get all the children of this resource. May optionally filter the children so only those
        matching certain parameters are returned. May optionally sort the children by an
        indexable attribute value key. The children will be returned as an instance of
        the given [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].

        :param v_type: The type of [view][ofrak.resource] to get the children as
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :param r_sort: Specifies which indexable attribute to use as the key to sort and the
        direction to sort
        :return:

        :raises NotFoundError: If a filter was provided and no resources match the provided filter
        """
        return await self.get_descendants_as_view(v_type, 1, r_filter, r_sort)

    async def get_only_child(self, r_filter: ResourceFilter = None) -> "Resource":
        """
        If a filter is provided, get the only child of this resource which matches the given
        filter. If a filter is not provided, gets the only child of this resource.

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If a filter is provided and more or fewer than one child matches
        ``r_filter``
        :raises NotFoundError: If a filter is not provided and this resource has multiple children
        """
        return await self.get_only_descendant(1, r_filter)

    async def get_only_child_as_view(self, v_type: Type[RV], r_filter: ResourceFilter = None) -> RV:
        """
        If a filter is provided, get the only child of this resource which matches the given
        filter. If a filter is not provided, gets the only child of this resource. The child will
        be returned as an instance of the given
        [viewable tag][ofrak.model.viewable_tag_model.ViewableResourceTag].

        :param v_type: The type of [view][ofrak.resource] to get the child as
        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :return:

        :raises NotFoundError: If a filter is provided and more or fewer than one child matches
        ``r_filter``
        :raises NotFoundError: If a filter is not provided and this resource has multiple children
        """
        return await self.get_only_descendant_as_view(v_type, 1, r_filter)

    async def delete(self):
        """
        Delete this resource and all of its descendants.

        :return:
        """
        self._component_context.resources_deleted.add(self._resource.id)

        for child_r in await self.get_children():
            await child_r.delete()

        self._resource.is_modified = True
        self._resource.is_deleted = True

    async def flush_to_disk(self, path: str):
        """
        Recursively repack the resource and write its data out to a file on disk. If this is a
        dataless resource, creates an empty file.

        :param path: Path to the file to write out to. The file is created if it does not exist.
        """
        await self.pack_recursively()
        data = await self.get_data()
        if data is not None:
            with open(path, "wb") as f:
                f.write(data)
        else:
            # Create empty file
            with open(path, "wb") as f:
                pass

    def __repr__(self):
        properties = [
            f"resource_id={self._resource.id.hex()}",
            f"tag=[{','.join([tag.__name__ for tag in self._resource.tags])}]",
        ]
        if self._resource.data_id:
            properties.append(f"data={self._resource.data_id.hex()}")
        return f"{type(self).__name__}(" + ", ".join(properties) + f")"

    async def summarize(self) -> str:
        """
        Create a string summary of this resource, including specific tags, attribute types,
        and the data offsets of this resource in the parent and root (if applicable).

        Not that this is not a complete string representation of the resource: not all tags are
        included, and only the types of attributes are included, not their values. It is a
        summary which gives a high level overview of the resource.
        """
        attributes_info = ", ".join(attrs_type.__name__ for attrs_type in self._resource.attributes)

        if self._resource.data_id:
            root_data_range = await self.get_data_range_within_root()
            parent_data_range = await self.get_data_range_within_parent()
            data = await self.get_data()
            if len(data) <= 128:
                # Convert bytes to string to check .isprintable without doing .decode. Note that
                # not all ASCII is printable, so we have to check both decodable and printable
                raw_data_str = "".join(map(chr, data))
                if raw_data_str.isascii() and raw_data_str.isprintable():
                    data_string = f'data_ascii="{data.decode("ascii")}"'
                else:
                    data_string = f"data_hex={data.hex()}"
            else:
                sha256 = hashlib.sha256()
                sha256.update(data)
                data_string = f"data_hash={sha256.hexdigest()[:8]}"
            data_info = (
                f", global_offset=({hex(root_data_range.start)}-{hex(root_data_range.end)})"
                f", parent_offset=({hex(parent_data_range.start)}-{hex(parent_data_range.end)})"
                f", {data_string}"
            )
        else:
            data_info = ""
        return (
            f"{self.get_id().hex()}: [caption=({self.get_caption()}), "
            f"attributes=({attributes_info}){data_info}]"
        )

    async def summarize_tree(
        self,
        r_filter: ResourceFilter = None,
        r_sort: ResourceSort = None,
        indent: str = "",
    ) -> str:
        """
        Create a string summary of this resource and its (optionally filtered and/or sorted)
        descendants. The summaries of each resource are the same as the result of
        [summarize][ofrak.resource.Resource.summarize], organized into a tree structure.
        If a filter parameter is provided, it is applied recursively: the children of this
        resource will be filtered, then only those children matching
        the filter be displayed, and then the same filter will be applied to their children,
        etc. For example,

        :param r_filter: Contains parameters which resources must match to be returned, including
        any tags it must have and/or values of indexable attributes
        :param r_sort: Specifies which indexable attribute to use as the key to sort and the
        direction to sort
        """
        SPACER_BLANK = "   "
        SPACER_LINE = "───"

        children = cast(
            List[Resource], list(await self.get_children(r_filter=r_filter, r_sort=r_sort))
        )

        if children:
            if indent == "":
                tree_string = "┌"
            else:
                tree_string = "┬"
        else:
            tree_string = "─"

        tree_string += f"{await self.summarize()}\n"

        # All children but the last should display as a "fork" in the drop-down tree
        # After the last child, a vertical line should not be drawn as part of the indent
        # Both of those needs are handled here
        child_formatting: List[Tuple[str, str]] = [
            ("├", indent + "│" + SPACER_BLANK) for _ in children[:-1]
        ]
        child_formatting.append(("└", indent + " " + SPACER_BLANK))

        for child, (branch_symbol, child_indent) in zip(children, child_formatting):
            child_tree_string = await child.summarize_tree(
                r_filter=r_filter, r_sort=r_sort, indent=child_indent
            )
            tree_string += f"{indent}{branch_symbol}{SPACER_LINE}{child_tree_string}"
        return tree_string


class ResourceFactory:
    """
    Factory for creating [Resource][ofrak.resource.Resource].
    """

    def __init__(
        self,
        id_service: IDServiceInterface,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        job_service: JobServiceInterface,
    ):
        self._id_service = id_service
        self._data_service = data_service
        self._resource_service = resource_service
        self._job_service = job_service

    async def create(
        self,
        job_id: bytes,
        resource_id: bytes,
        resource_context: ResourceContext,
        resource_view_context: ResourceViewContext,
        component_context: ComponentContext,
        job_context: Optional[JobRunContext] = None,
    ) -> Resource:
        """
        Create a resource from a resource_id.

        :param job_id:
        :param resource_id:
        :param resource_context:
        :param resource_view_context:
        :param component_context:
        :param job_context:
        """
        resource_m = resource_context.resource_models.get(resource_id)
        if resource_m is None:
            resource_m = MutableResourceModel.from_model(
                await self._resource_service.get_by_id(resource_id)
            )
            resource_context.resource_models[resource_id] = resource_m

        return next(
            iter(
                self._create(
                    job_id,
                    [resource_m],
                    resource_context,
                    resource_view_context,
                    component_context,
                    job_context,
                )
            )
        )

    async def create_many(
        self,
        job_id: bytes,
        resource_ids: Iterable[bytes],
        resource_context: ResourceContext,
        resource_view_context: ResourceViewContext,
        component_context: ComponentContext,
        job_context: Optional[JobRunContext] = None,
    ) -> Iterable[Resource]:
        """
        Create Resources from resource_ids.

        :param job_id:
        :param resource_ids:
        :param resource_context:
        :param resource_view_context:
        :param component_context:
        :param job_context:
        """
        resource_models_minus_missing: List[Union[MutableResourceModel, int]] = []
        missing_ids: List[bytes] = []

        resource_m: MutableResourceModel

        for resource_id in resource_ids:
            resource_m = resource_context.resource_models.get(resource_id)  # type: ignore
            if resource_m is None:
                resource_models_minus_missing.append(len(missing_ids))
                missing_ids.append(resource_id)
            else:
                resource_models_minus_missing.append(resource_m)

        fetched_models: List[ResourceModel] = list(
            await self._resource_service.get_by_ids(missing_ids)
        )

        resource_models = []
        for resource_model_or_idx in resource_models_minus_missing:
            if type(resource_model_or_idx) is int:
                resource_m = MutableResourceModel.from_model(
                    fetched_models[cast(int, resource_model_or_idx)]
                )
                resource_models.append(resource_m)
                resource_context.resource_models[resource_m.id] = resource_m
            else:
                resource_models.append(cast(MutableResourceModel, resource_model_or_idx))

        return self._create(
            job_id,
            resource_models,
            resource_context,
            resource_view_context,
            component_context,
            job_context,
        )

    def _create(
        self,
        job_id: bytes,
        resource_models: List[MutableResourceModel],
        resource_context: ResourceContext,
        resource_view_context: ResourceViewContext,
        component_context: ComponentContext,
        job_context: Optional[JobRunContext] = None,
    ) -> Iterable[Resource]:
        for resource_m in resource_models:
            yield Resource(
                job_id,
                resource_m,
                resource_context,
                resource_view_context,
                job_context,
                component_context,
                self,
                self._id_service,
                self._data_service,
                self._resource_service,
                self._job_service,
            )
