from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Any, Tuple, Optional

from ofrak.model.resource_model import (
    ResourceModel,
    ResourceIndexedAttribute,
    ResourceModelDiff,
)
from ofrak.model.tag_model import ResourceTag
from ofrak.service.abstract_ofrak_service import AbstractOfrakService


class ResourceServiceWalkError(RuntimeError):
    pass


class ResourceFilterCondition(Enum):
    AND = 1
    OR = 2


@dataclass
class ResourceAttributeFilter:
    attribute: ResourceIndexedAttribute


@dataclass
class ResourceAttributeRangeFilter(ResourceAttributeFilter):
    """
    A resource's [index][ofrak.model.resource_model.index] value must be within a range. The range
    must be bounded with either a maximum or minimum. The maximum is exclusive, i.e. if the index
    value is equal to the max, then the resource is excluded.
    """

    min: Any = None
    max: Any = None


@dataclass
class ResourceAttributeValueFilter(ResourceAttributeFilter):
    value: Any


@dataclass
class ResourceAttributeValuesFilter(ResourceAttributeFilter):
    values: Tuple[Any, ...]


@dataclass
class ResourceFilter:
    include_self: bool = False
    tags: Optional[Iterable[ResourceTag]] = None
    tags_condition: ResourceFilterCondition = ResourceFilterCondition.AND
    attribute_filters: Optional[Iterable[ResourceAttributeFilter]] = None

    @classmethod
    def with_tags(cls, *tags: ResourceTag):
        return ResourceFilter(tags=tags)


class ResourceSortDirection(Enum):
    DESCENDANT = 0
    ASCENDANT = 1


@dataclass
class ResourceSort:
    attribute: ResourceIndexedAttribute
    direction: ResourceSortDirection = ResourceSortDirection.ASCENDANT


class ResourceServiceInterface(AbstractOfrakService, metaclass=ABCMeta):
    """
    Stores [ResourceModels][ofrak.model.resource_model.ResourceModel] in a tree structure and
    provides methods to walk that tree according to given
    [ResourceFilters][ofrak.service.resource_service_i.ResourceFilter]. Resource instantiation is
    handled by the [ResourceFactory][ofrak.resource.ResourceFactory].
    """

    @abstractmethod
    async def create(self, resource: ResourceModel) -> ResourceModel:
        """
        Add a [ResourceModel][ofrak.model.resource_model.ResourceModel] to the resource service
        database according to the given model. If the ``resource`` model says it has a parent,
        ``resource`` will be added as a child of that parent.

        :param resource: The resource model to add to the database

        :raises AlreadyExistError: If ``resource`` has an ID which already exists in the database
        :raises NotFoundError: If ``resource`` has a parent ID but no resource with that ID exists

        :return: The same model which was passed in, with no changes

        """
        raise NotImplementedError()

    @abstractmethod
    async def get_root_resources(self) -> Iterable[ResourceModel]:
        """
        Get all of the root resources known to this resource service. Any resource created
        without a parent will be returned by this method.

        :return: All resources with no parents
        """
        raise NotImplementedError()

    @abstractmethod
    async def verify_ids_exist(self, resource_ids: Iterable[bytes]) -> Iterable[bool]:
        """
        Check if a number of resource IDs exist in the resource store. This is useful for
        filtering out IDs of resources which have been deleted.

        :param resource_ids: Iterable of resource IDs to check for

        :return: A boolean for each resource ID, True if it exists in the store and False otherwise
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_by_data_ids(self, data_ids: Iterable[bytes]) -> Iterable[ResourceModel]:
        """
        Get the resource models with a given sequence of data IDs.

        :param data_ids: A list of valid data IDs

        :raises NotFoundError: If there is not a resource for all of the IDs in `data_ids`

        :return: A sequence of resource models each with one of the given data IDs, in the same
        order which `data_ids` was given in.
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_by_ids(self, resource_ids: Iterable[bytes]) -> Iterable[ResourceModel]:
        """
        Get the resource models with a given sequence of resource IDs.

        :param resource_ids: A list of valid resource IDs

        :raises NotFoundError: If there is not a resource for all of the IDs in `resource_ids`

        :return: A sequence of resource models each with one of the given resource IDs, in the same
        order which `resource_ids` was given in.
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_by_id(self, resource_id: bytes) -> ResourceModel:
        """
        Get the resource model with a given resource ID.

        :param resource_id: A valid resource ID

        :raises NotFoundError: If there is not a resource with resource ID `resource_id`

        :return: The resource model with ID matching `resource_id`
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_depths(self, resource_ids: Iterable[bytes]) -> Iterable[int]:
        """
        Get the depth of each resource in `resource_ids`.

        :param resource_ids: A list of valid resource IDs

        :raises NotFoundError: If there is not a resource for all of the IDs in `resource_ids`

        :return: A sequence of resource model depths, in the same order which `resource_ids`
        was given in.
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_ancestors_by_id(
        self,
        resource_id: bytes,
        max_count: int = -1,
        r_filter: Optional[ResourceFilter] = None,
    ) -> Iterable[ResourceModel]:
        """
        Get the resource models of the ancestors of a resource with a given ID. These ancestors
        may be filtered by an optional filter argument. A maximum count of ancestors may also be
        given, to cap the number of (filtered or unfiltered) ancestors returned.

        :param resource_id: ID of resource to get ancestors of
        :param max_count: Optional argument to cap the number of models returned; if set to -1
        (default) then any number of ancestors may be returned
        :param r_filter: Optional resource filter for the resource models returned; if set to
        `None`, all ancestors may be returned (the model for `resource_id` is excluded),
        otherwise all ancestors matching the filter may be returned (possibly including the model
        for `resource_id`), up to the maximum allowed by `max_count`

        :raises NotFoundError: If there is not a resource with resource ID `resource_id`

        :return: As many ancestors of `resource_id` matching `r_filter` as `max_count`
        allows, in order of reverse depth (deeper resources first, root last)
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_descendants_by_id(
        self,
        resource_id: bytes,
        max_count: int = -1,
        max_depth: int = -1,
        r_filter: Optional[ResourceFilter] = None,
        r_sort: Optional[ResourceSort] = None,
    ) -> Iterable[ResourceModel]:
        """
        Get the resource models of the descendants of a resource with a given ID. These descendants
        may be filtered by an optional filter argument. A maximum count of descendants may also be
        given, to cap the number of (filtered or unfiltered) descendants returned. A maximum
        depth may also be given, to limit how deep to search for descendants.

        :param resource_id: ID of resource to get descendants of
        :param max_count: Optional argument to cap the number of models returned; if set to -1
        (default) then any number of descendants may be returned
        :param max_depth: Optional argument to limit the depth to search for descendants; if set
        to -1 (default) then descendants of any depth may be returned; if set to 1, for example,
        only children of `resource_id` may be returned
        :param r_filter: Optional resource filter for the resource models returned; if set to
        `None` all descendants may be returned (the model for `resource_id` is excluded),
        otherwise all descendants matching the filter may be returned (possibly including the model
        for `resource_id`), up to the maximum allowed by `max_count`
        :param r_sort: Optional logic to order the returned descendants by the value of a
        specific attribute of each descendant

        :raises NotFoundError: If there is not a resource with resource ID `resource_id`

        :return: As many descendants of `resource_id` matching `r_filter` as `max_count`
        allows, in order specified by `r_sort`. If `r_sort` is None, no specific ordering is
        guaranteed.
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_siblings_by_id(
        self,
        resource_id: bytes,
        max_count: int = -1,
        r_filter: Optional[ResourceFilter] = None,
        r_sort: Optional[ResourceSort] = None,
    ) -> Iterable[ResourceModel]:
        """
        Get the resource models of the siblings of a resource with a given ID. These siblings
        may be filtered by an optional filter argument. A maximum count of siblings may also be
        given, to cap the number of (filtered or unfiltered) siblings returned.

        :param resource_id: ID of resource to get siblings of
        :param max_count: Optional argument to cap the number of models returned; if set to -1
        (default) then any number of siblings may be returned
        :param r_filter: Optional resource filter for the resource models returned; if set to
        None all siblings may be returned (the model for `resource_id` is excluded),
        otherwise all siblings matching the filter may be returned (possibly including the model
        for `resource_id`), up to the maximum allowed by `max_count`
        :param r_sort: Optional logic to order the returned siblings by the value of a
        specific attribute of each sibling

        :raises NotFoundError: If there is not a resource with resource ID `resource_id`
        :raises NotFoundError: If the resource with ID `resource_id` does not have siblings
        because it is a root


        :return: As many siblings of `resource_id` matching `r_filter` as `max_count`
        allows, in order specified by `r_sort`. If `r_sort` is None, no specific ordering is
        guaranteed.
        """
        raise NotImplementedError()

    @abstractmethod
    async def update(self, resource_diff: ResourceModelDiff) -> ResourceModel:
        """
        Modify a stored resource model according to the differences in the given diff object.

        :param resource_diff: Diff object containing changes to a resource model, as well as the
        resource ID of the model to update

        :raises NotFoundError: If there is not a resource with resource ID matching the ID in
        `resource_diff`

        :return: The updated resource model (with changes applied)
        """
        raise NotImplementedError()

    @abstractmethod
    async def rebase_resource(self, resource_id: bytes, new_parent_id: bytes):
        """
        Move a resource which was a child to instead be a child of a different resource.

        :param resource_id: resource ID of the resource to rebase
        :param new_parent_id: resource ID of the new parent resource for `resource_id`

        :raises NotFoundError: If there is not a resource with resource ID `resource_id`
        :raises NotFoundError: If there is not a resource with resource ID `new_parent_id`
        """
        raise NotImplementedError()

    @abstractmethod
    async def delete_resource(self, resource_id: bytes):
        """
        Delete a resource by ID and all of its children, removing them from the database. If no
        resource for the given ID is found, it is assumed the resource has already been deleted
        (does not raise an error).

        :param resource_id: The ID of the resource to delete
        """
        raise NotImplementedError()
