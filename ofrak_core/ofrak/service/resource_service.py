import bisect
import itertools
import logging
import math
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Set, Optional, Iterable, Tuple, Any, TypeVar, Generic

from ofrak.model.resource_model import (
    ResourceModel,
    ResourceModelDiff,
    ResourceIndexedAttribute,
)
from ofrak.model.tag_model import ResourceTag
from ofrak.service.resource_service_i import (
    ResourceServiceInterface,
    ResourceFilter,
    ResourceSort,
    ResourceAttributeFilter,
    ResourceAttributeRangeFilter,
    ResourceAttributeValueFilter,
    ResourceAttributeValuesFilter,
    ResourceSortDirection,
    ResourceFilterCondition,
    ResourceServiceWalkError,
)
from ofrak_type.error import NotFoundError, AlreadyExistError
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)
T = TypeVar("T", str, int, float, bytes)


class LowValue:
    def __lt__(self, other):
        return True


class HighValue:
    def __lt__(self, other):
        return False


LOW_VALUE = LowValue()
HIGH_VALUE = HighValue()


class ResourceNode:
    model: ResourceModel
    parent: Optional["ResourceNode"]
    _children: List["ResourceNode"]
    _ancestor_ids: Dict[bytes, int]
    _descendant_count: int
    _depth: int

    def __init__(self, model: ResourceModel, parent: Optional["ResourceNode"]):
        self.model = model
        self.parent = parent
        self._children = []
        self._ancestor_ids = dict()
        self._descendant_count = 0
        self._depth = 0
        if self.parent is not None:
            self.parent.add_child(self)
            self.model.parent_id = self.parent.model.id
        else:
            self.model.parent_id = None

    def add_child(self, child: "ResourceNode"):
        child._depth = self._depth + 1

        child._ancestor_ids = {
            parent_id: parent_depth + 1 for parent_id, parent_depth in self._ancestor_ids.items()
        }
        child._ancestor_ids[self.model.id] = 1

        parent: Optional[ResourceNode] = self
        while parent is not None:
            parent._descendant_count += child._descendant_count + 1
            parent = parent.parent

        self._children.append(child)

    def remove_child(self, child: "ResourceNode"):
        self._children.remove(child)
        parent: Optional[ResourceNode] = self
        while parent is not None:
            parent._descendant_count -= child._descendant_count + 1
            parent = parent.parent

        ids_to_clear = list(child._ancestor_ids.keys())

        def remove_ancestor_ids(descendent: "ResourceNode"):
            for ancestor_id in ids_to_clear:
                del descendent._ancestor_ids[ancestor_id]

            for _descendent in descendent._children:
                remove_ancestor_ids(_descendent)

        remove_ancestor_ids(child)

    def has_ancestor(self, id: bytes, max_depth: int = -1, include_self: bool = False) -> bool:
        if include_self and id == self.model.id:
            return True
        ancestor_depth = self._ancestor_ids.get(id)
        if ancestor_depth is None:
            return False
        if max_depth < 0:
            return True
        return ancestor_depth <= max_depth

    def walk_ancestors(self, include_self: bool) -> Iterable["ResourceNode"]:
        if include_self:
            yield self
        parent = self.parent
        while parent is not None:
            yield parent
            parent = parent.parent

    def get_depth(self) -> int:
        return self._depth

    def get_descendant_count(self) -> int:
        return self._descendant_count

    def walk_descendants(
        self, include_self: bool, max_depth: int, _depth: int = 0
    ) -> Iterable["ResourceNode"]:
        if include_self:
            yield self
        if 0 <= max_depth <= _depth:
            return
        for child in self._children:
            yield from child.walk_descendants(True, max_depth, _depth + 1)

    def __lt__(self, other):
        if not isinstance(other, ResourceNode):
            return False
        return self.model.id < other.model.id

    def __eq__(self, other):
        if not isinstance(other, ResourceNode):
            return False
        return self.model.id == other.model.id

    def __hash__(self):
        return hash(self.model.id)


class ResourceAttributeIndex(Generic[T]):
    _attribute: ResourceIndexedAttribute[T]
    index: List[Tuple[Any, ResourceNode]]
    values_by_node_id: Dict[bytes, Any]

    def __init__(self, attribute: ResourceIndexedAttribute[T]):
        self._attribute = attribute  # type: ignore
        self.index = []
        self.values_by_node_id = dict()

    def add_resource_attribute(
        self,
        value: T,
        resource: ResourceNode,
    ):
        if resource.model.id in self.values_by_node_id:
            raise ValueError(
                f"The provided resource {resource.model.id.hex()} is already in the "  # type: ignore
                f"index for {self._attribute.__name__}"
            )
        value_index = bisect.bisect_left(self.index, (value, resource))
        if value_index < len(self.index) and self.index[value_index][1] == resource:
            raise RuntimeError(
                "If this error is raised, an index has gotten out of sync with "
                "itself. An error should have been raised a few lines earlier."
            )
        self.index.insert(value_index, (value, resource))
        self.values_by_node_id[resource.model.id] = value

    def remove_resource_attribute(
        self,
        resource: ResourceNode,
    ):
        if resource.model.id not in self.values_by_node_id:
            raise ValueError(
                f"The provided resource {resource.model.id.hex()} is not in the "  # type: ignore
                f"index for {self._attribute.__name__}"
            )
        value = self.values_by_node_id[resource.model.id]
        value_index = bisect.bisect_left(self.index, (value, resource))
        if value_index < len(self.index) and self.index[value_index][1] != resource:
            raise RuntimeError(
                "If this error is raised, an index has gotten out of sync with "
                "itself. An error should have been raised a few lines earlier."
            )
        self.index.pop(value_index)
        del self.values_by_node_id[resource.model.id]


class AttributeIndexDict(defaultdict):
    """
    `defaultdict` that passes the missing key to the default factory.

    See:
    <https://stackoverflow.com/questions/2912231/is-there-a-clever-way-to-pass-the-key-to-defaultdicts-default-factory>
    """

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        else:
            ret = self[key] = self.default_factory(key)
            return ret


class ResourceSortLogic(Generic[T], ABC):
    @abstractmethod
    def has_effect(self) -> bool:
        raise NotImplementedError()

    def get_match_count(self) -> int:
        raise NotImplementedError()

    def _get_attribute_value(self, resource: ResourceModel) -> Optional[T]:
        raise NotImplementedError()

    def sort(self, resources: Iterable[ResourceModel]) -> Iterable[ResourceModel]:
        raise NotImplementedError()

    def walk(self) -> Iterable[ResourceNode]:
        raise NotImplementedError()

    def get_attribute(self) -> Optional[ResourceIndexedAttribute[T]]:
        raise NotImplementedError()

    def get_direction(self) -> ResourceSortDirection:
        raise NotImplementedError()

    @staticmethod
    def create(
        r_sort: Optional[ResourceSort],
        attribute_indexes: Dict[ResourceIndexedAttribute[T], ResourceAttributeIndex],
    ) -> "ResourceSortLogic[T]":
        if r_sort is None:
            return NullResourceSortLogic()
        attribute_index = attribute_indexes[r_sort.attribute].index
        return ActiveResourceSortLogic[T](r_sort.attribute, attribute_index, r_sort.direction)


class ActiveResourceSortLogic(ResourceSortLogic[T]):
    def __init__(
        self,
        attribute: ResourceIndexedAttribute[T],
        index: List[Tuple[Any, ResourceNode]],
        direction: ResourceSortDirection = ResourceSortDirection.ASCENDANT,
    ):
        self.attribute: ResourceIndexedAttribute[T] = attribute  # type: ignore
        self.index: List[Tuple[Any, ResourceNode]] = index
        self.direction: ResourceSortDirection = direction

    def has_effect(self) -> bool:
        return True

    def get_match_count(self) -> int:
        return len(self.index)

    def get_attribute(self) -> ResourceIndexedAttribute[T]:
        return self.attribute

    def get_direction(self) -> ResourceSortDirection:
        return self.direction

    def _get_attribute_value(self, resource: ResourceModel) -> T:
        value = self.attribute.get_value(resource)
        if value is None:
            raise ValueError()
        else:
            return value

    def sort(self, resources: Iterable[ResourceModel]) -> Iterable[ResourceModel]:
        if self.attribute is None:
            raise ValueError("No attribute specified to sort on")
        reverse = self.direction != ResourceSortDirection.ASCENDANT
        return sorted(resources, key=self._get_attribute_value, reverse=reverse)

    def walk(self) -> Iterable[ResourceNode]:
        if self.index is None:
            raise ResourceServiceWalkError("Cannot walk a ResourceSortLogic with no index!")
        if self.direction is ResourceSortDirection.ASCENDANT:
            index = 0
            increment = 1
        else:
            index = len(self.index) - 1
            increment = -1
        max_index = len(self.index)
        while 0 <= index < max_index:
            yield self.index[index][1]
            index += increment


class NullResourceSortLogic(ResourceSortLogic):
    def has_effect(self) -> bool:
        return False

    def get_attribute(self) -> None:
        return None


class ResourceFilterLogic(Generic[T], ABC):
    def get_attribute(self) -> Optional[ResourceIndexedAttribute[T]]:
        return None

    @abstractmethod
    def filter(self, value: ResourceNode) -> bool:
        pass

    @abstractmethod
    def get_match_count(self) -> int:
        pass

    @abstractmethod
    def walk(self, direction: ResourceSortDirection) -> Iterable[ResourceNode]:
        pass

    @classmethod
    def get_attribute_value(
        cls, resource: ResourceNode, attribute_type: ResourceIndexedAttribute[T]
    ) -> Optional[T]:
        return attribute_type.get_value(resource.model)


class ResourceAttributeFilterLogic(ResourceFilterLogic[T], ABC):
    def __init__(
        self,
        attribute: ResourceIndexedAttribute[T],
        index: List[Tuple[T, ResourceNode]],
    ):
        self.attribute: ResourceIndexedAttribute[T] = attribute  # type: ignore
        self.index: List[Tuple[T, ResourceNode]] = index
        self._cached_ranges: Optional[Tuple[Range, ...]] = None

    def get_attribute(self) -> Optional[ResourceIndexedAttribute[T]]:
        return self.attribute

    @abstractmethod
    def _compute_ranges(self) -> Iterable[Range]:
        pass

    def walk(self, direction: ResourceSortDirection) -> Iterable[ResourceNode]:
        if self._cached_ranges is None:
            self._cached_ranges = tuple(sorted(self._compute_ranges(), key=lambda r: r.start))
        cached_ranges: Iterable[Range] = ()
        if direction is ResourceSortDirection.ASCENDANT:
            cached_ranges = self._cached_ranges
        else:
            cached_ranges = tuple(reversed(self._cached_ranges))

        for index_range in cached_ranges:
            if direction is ResourceSortDirection.ASCENDANT:
                index = index_range.start
                increment = 1
            else:
                index = index_range.end - 1
                increment = -1
            min_index = index_range.start
            max_index = index_range.end
            while min_index <= index < max_index:
                yield self.index[index][1]
                index += increment

    def get_match_count(self) -> int:
        if self._cached_ranges is None:
            self._cached_ranges = tuple(sorted(self._compute_ranges(), key=lambda r: r.start))
        return sum(r.length() for r in self._cached_ranges)


class ResourceAttributeRangeFilterLogic(ResourceAttributeFilterLogic, Generic[T]):
    def __init__(
        self,
        attribute: ResourceIndexedAttribute[T],
        index: List[Tuple[T, ResourceNode]],
        min: T = None,
        max: T = None,
    ):
        if min is None and max is None:
            raise ValueError("Invalid filter, either a min, a max or both must be provided")
        super().__init__(attribute, index)
        self.min: Optional[T] = min
        self.max: Optional[T] = max

    def _compute_ranges(self) -> Iterable[Range]:
        if self.min is not None:
            min_index = bisect.bisect_left(self.index, (self.min, LOW_VALUE))
        else:
            min_index = 0
        if self.max is not None:
            # TODO: There should most likely be a +1 in here
            max_index = bisect.bisect_left(self.index, (self.max, LOW_VALUE))
        else:
            max_index = len(self.index)
        return (Range(min_index, max_index),)

    def filter(self, resource: ResourceNode) -> bool:
        value = self.get_attribute_value(resource, self.attribute)
        if value is None:
            return False
        if self.min is not None and self.max is not None:
            return self.min <= value < self.max
        if self.min is not None:
            return self.min <= value
        elif self.max is not None:
            return value < self.max
        else:
            raise ValueError("Invalid filter, either a min, a max or both must be provided")


class ResourceAttributeValueFilterLogic(ResourceAttributeFilterLogic, Generic[T]):
    def __init__(
        self,
        attribute: ResourceIndexedAttribute[T],
        index: List[Tuple[T, ResourceNode]],
        value: T,
    ):
        super().__init__(attribute, index)
        self.value: T = value

    def _compute_ranges(self) -> Iterable[Range]:
        return (
            Range(
                bisect.bisect_left(self.index, (self.value, LOW_VALUE)),
                bisect.bisect_right(self.index, (self.value, HIGH_VALUE)),
            ),
        )

    def filter(self, resource: ResourceNode) -> bool:
        value = self.get_attribute_value(resource, self.attribute)
        if value is None:
            return False
        return value == self.value


class ResourceAttributeValuesFilterLogic(ResourceAttributeFilterLogic, Generic[T]):
    def __init__(
        self,
        attribute: ResourceIndexedAttribute[T],
        index: List[Tuple[T, ResourceNode]],
        values: Tuple[T, ...],
    ):
        super().__init__(attribute, index)
        self.index = index
        self.values: Set[T] = set(values)

    def _compute_ranges(self) -> Iterable[Range]:
        for value in self.values:
            yield Range(
                bisect.bisect_left(self.index, (value, LOW_VALUE)),
                bisect.bisect_right(self.index, (value, HIGH_VALUE)),
            )

    def filter(self, resource: ResourceNode) -> bool:
        value = self.get_attribute_value(resource, self.attribute)
        if value is None:
            return False
        return value in self.values


class ResourceTagOrFilterLogic(ResourceFilterLogic):
    def __init__(
        self,
        indexes: Dict[ResourceTag, Set[ResourceNode]],
        tags: Tuple[ResourceTag, ...],
    ):
        if len(tags) == 0:
            raise ValueError(
                "Cannot instantiate the ResourceTagOrFilterLogic class with an empty set of tags "
                "to filter on."
            )
        self.indexes = indexes
        self.tags = tags

    def filter(self, resource: ResourceNode) -> bool:
        for tag in self.tags:
            if resource.model.has_tag(tag):
                return True
        return False

    def get_match_count(self) -> int:
        count = 0
        for tag in self.tags:
            count += len(self.indexes[tag])
        return count

    def walk(self, direction: ResourceSortDirection) -> Iterable[ResourceNode]:
        processed_ids = set()
        for tag in self.tags:
            for resource in self.indexes[tag]:
                resource_m = resource.model
                if resource_m.id in processed_ids:
                    continue
                processed_ids.add(resource_m.id)
                yield resource


class ResourceTagAndFilterLogic(ResourceFilterLogic):
    def __init__(
        self,
        indexes: Dict[ResourceTag, Set[ResourceNode]],
        tags: Tuple[ResourceTag, ...],
    ):
        if len(tags) == 0:
            raise ValueError(
                "Cannot instantiate the ResourceTagAndFilterLogic class with an empty set of tags "
                "to filter on."
            )
        self.indexes: Dict[ResourceTag, Set[ResourceNode]] = indexes
        self.tags = tags

        self._walk_tag: Optional[ResourceTag] = None
        self._filter_tags: Optional[Tuple[ResourceTag, ...]] = None

    def filter(self, resource: ResourceNode) -> bool:
        for tag in self.tags:
            if not resource.model.has_tag(tag):
                return False
        return True

    def _compute_tags(self) -> Tuple[ResourceTag, Optional[Tuple[ResourceTag, ...]]]:
        if self._walk_tag is not None:
            return self._walk_tag, self._filter_tags
        min_size = sys.maxsize
        walk_tag = None
        for tag in self.tags:
            index_size = len(self.indexes[tag])
            if index_size < min_size:
                walk_tag = tag
                min_size = index_size
        if walk_tag is None:
            # No tags in self.tags had fewer than sys.maxsize resources with that tag. Choose one
            # arbitrarily to be the walk tag then, since they all have equal (very high) cost.
            walk_tag = self.tags[0]
        self._walk_tag = walk_tag
        filter_tags = tuple(filter(lambda t: t != walk_tag, self.tags))
        self._filter_tags = filter_tags

        return walk_tag, filter_tags

    def get_match_count(self) -> int:
        walk_tag, _ = self._compute_tags()
        return len(self.indexes[walk_tag])

    def walk(self, direction: ResourceSortDirection) -> Iterable[ResourceNode]:
        walk_tag, filter_tags = self._compute_tags()
        main_index = self.indexes[walk_tag]
        for resource in main_index:
            if filter_tags is not None and len(filter_tags) > 0:
                for tag in filter_tags:
                    if resource in self.indexes[tag]:
                        yield resource
            else:
                yield resource


class ResourceAncestorFilterLogic(ResourceFilterLogic):
    def __init__(
        self,
        root: ResourceNode,
        include_root: bool = False,
        max_depth: int = -1,
    ):
        self.root = root
        self.include_root = include_root
        self.max_depth = max_depth

    def has_effect(self) -> bool:
        return self.root is not None

    def filter(self, resource: ResourceNode) -> bool:
        return resource.has_ancestor(self.root.model.id, self.max_depth, self.include_root)

    def get_match_count(self) -> int:
        count = self.root.get_descendant_count()
        if self.include_root:
            count += 1
        return count

    def walk(self, direction: ResourceSortDirection) -> Iterable[ResourceNode]:
        return self.root.walk_descendants(include_self=self.include_root, max_depth=self.max_depth)


class AggregateResourceFilterLogic:
    def __init__(self, filters: Tuple[ResourceFilterLogic, ...]):
        self.filters = filters

    @staticmethod
    def _create_attribute_filter(
        attribute_filter: ResourceAttributeFilter, attribute_index: List[Tuple[T, ResourceNode]]
    ) -> ResourceFilterLogic[T]:
        if isinstance(attribute_filter, ResourceAttributeRangeFilter):
            return ResourceAttributeRangeFilterLogic(
                attribute_filter.attribute,
                attribute_index,
                attribute_filter.min,
                attribute_filter.max,
            )
        elif isinstance(attribute_filter, ResourceAttributeValueFilter):
            return ResourceAttributeValueFilterLogic(
                attribute_filter.attribute, attribute_index, attribute_filter.value
            )
        elif isinstance(attribute_filter, ResourceAttributeValuesFilter):
            return ResourceAttributeValuesFilterLogic(
                attribute_filter.attribute, attribute_index, attribute_filter.values
            )
        else:
            raise ValueError(f"Unknown filter of type {type(attribute_filter).__name__}")

    @staticmethod
    def create(
        r_filter: Optional[ResourceFilter],
        tag_indexes: Dict[ResourceTag, Set[ResourceNode]],
        attribute_indexes: Dict[ResourceIndexedAttribute[T], ResourceAttributeIndex[T]],
        ancestor: ResourceNode = None,
        max_depth: int = -1,
    ) -> "AggregateResourceFilterLogic":
        filters: List[ResourceFilterLogic] = []
        if r_filter is not None:
            if r_filter.tags is not None:
                if r_filter.tags_condition is ResourceFilterCondition.AND:
                    filters.append(ResourceTagAndFilterLogic(tag_indexes, tuple(r_filter.tags)))
                else:
                    filters.append(ResourceTagOrFilterLogic(tag_indexes, tuple(r_filter.tags)))
            if r_filter.attribute_filters is not None:
                for attribute_filter in r_filter.attribute_filters:
                    filters.append(
                        AggregateResourceFilterLogic._create_attribute_filter(
                            attribute_filter, attribute_indexes[attribute_filter.attribute].index
                        )
                    )

            include_root = r_filter.include_self
        else:
            include_root = False
        if ancestor is not None:
            filters.append(ResourceAncestorFilterLogic(ancestor, include_root, max_depth))
        return AggregateResourceFilterLogic(tuple(filters))

    def ignore_filter(self, filter_logic: ResourceFilterLogic):
        if filter_logic is None:
            raise ValueError("Invalid index filter logic")
        self.filters = tuple(ix for ix in self.filters if ix != filter_logic)

    def has_effect(self) -> bool:
        return len(self.filters) > 0

    def filter(self, resource: ResourceNode) -> bool:
        for filter_logic in self.filters:
            if not filter_logic.filter(resource):
                return False
        return True


class ResourceService(ResourceServiceInterface):
    def __init__(self):
        self._resource_store: Dict[bytes, ResourceNode] = dict()
        self._resource_by_data_id_store: Dict[bytes, ResourceNode] = dict()
        self._attribute_indexes: Dict[
            ResourceIndexedAttribute[T], ResourceAttributeIndex[T]
        ] = AttributeIndexDict(ResourceAttributeIndex)
        self._tag_indexes: Dict[ResourceTag, Set[ResourceNode]] = defaultdict(set)
        self._root_resources: Dict[bytes, ResourceNode] = dict()

    def _add_resource_tag_to_index(self, tag: ResourceTag, resource: ResourceNode):
        for _tag in tag.tag_classes():
            self._tag_indexes[_tag].add(resource)

    def _remove_resource_tag_from_index(
        self,
        tag: ResourceTag,
        resource: ResourceNode,
        blacklist: Set[ResourceTag],
    ):
        for _tag in tag.tag_classes():
            if blacklist is not None and _tag in blacklist:
                continue
            self._tag_indexes[_tag].remove(resource)

    def _add_resource_attribute_to_index(
        self,
        indexable_attribute: ResourceIndexedAttribute[T],
        value: T,
        resource: ResourceNode,
    ):
        if value is None:
            return
        index = self._attribute_indexes[indexable_attribute]
        index.add_resource_attribute(value, resource)

    def _remove_resource_attribute_from_index(
        self,
        indexable_attribute: ResourceIndexedAttribute[T],
        resource: ResourceNode,
    ):
        index = self._attribute_indexes[indexable_attribute]
        index.remove_resource_attribute(resource)

    async def create(self, resource: ResourceModel) -> ResourceModel:
        if resource.id in self._resource_store:
            raise AlreadyExistError(f"A resource with id {resource.id.hex()} already exists!")
        if resource.parent_id is not None:
            parent_resource_node = self._resource_store.get(resource.parent_id)
            if parent_resource_node is None:
                raise NotFoundError(
                    f"The parent resource with id {resource.parent_id.hex()} does not exist"
                )
            LOGGER.debug(
                f"Creating resource {resource.id.hex()} as child of {resource.parent_id.hex()}"
            )
        else:
            parent_resource_node = None
            LOGGER.debug(f"Creating resource {resource.id.hex()}")
        resource_node = ResourceNode(resource, parent_resource_node)
        self._resource_store[resource.id] = resource_node
        if resource.data_id is not None:
            self._resource_by_data_id_store[resource.data_id] = resource_node
        if parent_resource_node is None:
            self._root_resources[resource.id] = resource_node

        # Take care of the indexes
        for tag in resource.tags:
            self._add_resource_tag_to_index(tag, resource_node)
        for indexable_attribute, value in resource.get_index_values().items():
            self._add_resource_attribute_to_index(indexable_attribute, value, resource_node)
        return resource

    async def get_root_resources(self) -> List[ResourceModel]:
        return [root_node.model for root_node in self._root_resources.values()]

    async def verify_ids_exist(self, resource_ids: Iterable[bytes]) -> Iterable[bool]:
        return [resource_id in self._resource_store for resource_id in resource_ids]

    async def get_by_data_ids(self, data_ids: Iterable[bytes]) -> Iterable[ResourceModel]:
        results = []
        for data_id in data_ids:
            resource_node = self._resource_by_data_id_store.get(data_id)
            if resource_node is None:
                raise NotFoundError(f"The resource with data ID {data_id.hex()} does not exist")
            results.append(resource_node.model)
        return results

    async def get_by_ids(self, resource_ids: Iterable[bytes]) -> Iterable[ResourceModel]:
        results = []
        for resource_id in resource_ids:
            resource_node = self._resource_store.get(resource_id)
            if resource_node is None:
                raise NotFoundError(f"The resource {resource_id.hex()} does not exist")
            results.append(resource_node.model)
        return results

    async def get_by_id(self, resource_id: bytes) -> ResourceModel:
        LOGGER.debug(f"Fetching resource {resource_id.hex()}")
        resource_node = self._resource_store.get(resource_id)
        if resource_node is None:
            raise NotFoundError(f"The resource {resource_id.hex()} does not exist")
        return resource_node.model

    async def get_depths(self, resource_ids: Iterable[bytes]) -> Iterable[int]:
        results = []
        for resource_id in resource_ids:
            resource_node = self._resource_store.get(resource_id)
            if resource_node is None:
                raise NotFoundError(f"The resource {resource_id.hex()} does not exist")
            results.append(resource_node.get_depth())
        return results

    async def get_ancestors_by_id(
        self,
        resource_id: bytes,
        max_count: int = -1,
        r_filter: Optional[ResourceFilter] = None,
    ) -> Iterable[ResourceModel]:
        LOGGER.debug(f"Fetching ancestor(s) of {resource_id.hex()}")
        resource_node = self._resource_store.get(resource_id)
        if resource_node is None:
            raise NotFoundError(f"The resource {resource_id.hex()} does not exist")
        r_filter_logic = AggregateResourceFilterLogic.create(
            r_filter,
            self._tag_indexes,
            self._attribute_indexes,
        )
        include_root = False if r_filter is None else r_filter.include_self
        resources = map(
            lambda n: n.model,
            filter(r_filter_logic.filter, resource_node.walk_ancestors(include_root)),
        )
        if max_count < 0:
            return resources
        return itertools.islice(resources, 0, max_count)

    async def get_descendants_by_id(
        self,
        resource_id: bytes,
        max_count: int = -1,
        max_depth: int = -1,
        r_filter: Optional[ResourceFilter] = None,
        r_sort: Optional[ResourceSort] = None,
    ) -> Iterable[ResourceModel]:
        # LOGGER.debug(f"Fetching descendant(s) of {resource_id.hex()}")
        resource_node = self._resource_store.get(resource_id)
        if resource_node is None:
            raise NotFoundError(f"The resource {resource_id.hex()} does not exist")

        aggregate_sort_logic = ResourceSortLogic.create(r_sort, self._attribute_indexes)
        aggregate_filter_logic = AggregateResourceFilterLogic.create(
            r_filter, self._tag_indexes, self._attribute_indexes, resource_node, max_depth
        )
        # This is the planning phase used to determine the best index to use for further filtering
        filter_logic: Optional[ResourceFilterLogic] = None
        filter_cost = sys.maxsize
        sort_cost = sys.maxsize
        if aggregate_sort_logic.has_effect():
            sort_cost = aggregate_sort_logic.get_match_count()
            if sort_cost == 0:
                return tuple()

        for _filter_logic in aggregate_filter_logic.filters:
            _filter_cost = _filter_logic.get_match_count()
            if _filter_cost == 0:
                return tuple()
            if (
                aggregate_sort_logic.has_effect()
                and aggregate_sort_logic.get_attribute() != _filter_logic.get_attribute()
            ):
                # The resources matching the filter would need to get sorted, making the
                # worst case # scenario more expensive
                _filter_cost = int(_filter_cost * math.log2(_filter_cost))
            if _filter_cost < filter_cost:
                filter_cost = _filter_cost
                filter_logic = _filter_logic

        # Use the estimated cost to pick the fastest way to compute the results
        if (
            filter_logic is not None
            and filter_logic.get_attribute() is not None
            and filter_logic.get_attribute() == aggregate_sort_logic.get_attribute()
        ):
            resource_nodes = filter_logic.walk(aggregate_sort_logic.get_direction())
            aggregate_filter_logic.ignore_filter(filter_logic)
            aggregate_sort_logic = NullResourceSortLogic()
        elif sort_cost < filter_cost:
            resource_nodes = aggregate_sort_logic.walk()
            aggregate_sort_logic = NullResourceSortLogic()
        elif filter_logic is not None:
            resource_nodes = filter_logic.walk(ResourceSortDirection.ASCENDANT)
            # No need to filter on that index since it serves as the root index
            aggregate_filter_logic.ignore_filter(filter_logic)

        if aggregate_filter_logic.has_effect():
            resource_nodes = filter(aggregate_filter_logic.filter, resource_nodes)
        resources: Iterable[ResourceModel] = map(lambda n: n.model, resource_nodes)
        if aggregate_sort_logic.has_effect():
            resources = aggregate_sort_logic.sort(resources)
        if max_count >= 0:
            resources = itertools.islice(resources, 0, max_count)
        return resources

    async def get_siblings_by_id(
        self,
        resource_id: bytes,
        max_count: int = -1,
        r_filter: Optional[ResourceFilter] = None,
        r_sort: Optional[ResourceSort] = None,
    ) -> Iterable[ResourceModel]:
        resource_node = self._resource_store.get(resource_id)
        if resource_node is None:
            raise NotFoundError(f"The resource {resource_id.hex()} does not exist")
        if resource_node.parent is None:
            raise NotFoundError(
                f"The resource {resource_id.hex()} does not have siblings as it is a root "
                f"resource."
            )
        return await self.get_descendants_by_id(
            resource_node.parent.model.id, max_count, 1, r_filter, r_sort
        )

    async def update(self, resource_diff: ResourceModelDiff) -> ResourceModel:
        LOGGER.debug(f"Saving resource {resource_diff.id.hex()}")
        resource_node = self._resource_store.get(resource_diff.id)
        if resource_node is None:
            raise NotFoundError(f"The resource with ID {resource_diff.id.hex()} does not exist")

        prev_resource = resource_node.model
        next_resource = resource_diff.apply(prev_resource)

        current_tags = next_resource.get_tags()
        # Update the tag indexes
        for tag_removed in resource_diff.tags_removed:
            self._remove_resource_tag_from_index(tag_removed, resource_node, set(current_tags))
        for tag_added in resource_diff.tags_added:
            self._add_resource_tag_to_index(tag_added, resource_node)

        # Update the attribute indexes
        indexable_attributes_removed = set()
        for attributes_removed in resource_diff.attributes_removed:
            for indexable_attribute_removed in attributes_removed.get_indexable_attributes():
                indexable_attributes_removed.add(indexable_attribute_removed)
                self._remove_resource_attribute_from_index(
                    indexable_attribute_removed, resource_node
                )
        indexable_attrs_indirectly_removed = next_resource.get_index_values_depending_on_indexes(
            indexable_attributes_removed
        )
        for indexable_attr_indirectly_removed in indexable_attrs_indirectly_removed.keys():
            self._remove_resource_attribute_from_index(
                indexable_attr_indirectly_removed, resource_node
            )

        indexable_attributes_added = set()
        for attributes_type_added, attributes_added in resource_diff.attributes_added.items():
            for indexable_attribute_added in attributes_added.get_indexable_attributes():
                indexable_attributes_added.add(indexable_attribute_added)
                self._add_resource_attribute_to_index(
                    indexable_attribute_added,
                    indexable_attribute_added.get_value(next_resource),
                    resource_node,
                )
        for indexable_attribute, value in next_resource.get_index_values_depending_on_indexes(
            indexable_attributes_added
        ).items():
            if indexable_attribute in indexable_attributes_added:
                # It was already added to the index in earlier steps
                continue
            elif value is None:
                # Index can only be calculated if all the required attributes are present
                # None value indicates one or more required attributes are not present
                # Therefore don't try to index this resource by this index type
                continue
            else:
                self._add_resource_attribute_to_index(indexable_attribute, value, resource_node)

        resource_node.model = next_resource
        return next_resource

    async def rebase_resource(self, resource_id: bytes, new_parent_id: bytes):
        resource_node = self._resource_store.get(resource_id)
        if resource_node is None:
            raise NotFoundError(f"The resource {resource_id.hex()} does not exist")

        new_parent_resource_node = self._resource_store.get(new_parent_id)
        if new_parent_resource_node is None:
            raise NotFoundError(f"The new parent resource {resource_id.hex()} does not exist")

        former_parent_resource_node = resource_node.parent
        if former_parent_resource_node is not None:
            former_parent_resource_node.remove_child(resource_node)
        new_parent_resource_node.add_child(resource_node)
        resource_node.parent = new_parent_resource_node
        resource_node.model.parent_id = new_parent_id

    async def delete_resource(self, resource_id: bytes):
        resource_node = self._resource_store.get(resource_id)
        if resource_node is None:
            # Already deleted, probably by an ancestor calling the recursive func below
            return

        former_parent_resource_node = resource_node.parent
        if former_parent_resource_node is not None:
            former_parent_resource_node.remove_child(resource_node)

        def _delete_resource_helper(_resource_node: ResourceNode):
            for child in _resource_node._children:
                _delete_resource_helper(child)

            for indexable_attribute, val in _resource_node.model.get_index_values().items():
                try:
                    self._remove_resource_attribute_from_index(indexable_attribute, _resource_node)
                except ValueError as e:
                    if val is None:
                        # Index value could not be calculated, so it is not surprising it was not
                        # in the index
                        continue
                    else:
                        raise e

            tag_removal_blacklist: Set[ResourceTag] = set()
            for tag in _resource_node.model.tags:
                self._remove_resource_tag_from_index(tag, _resource_node, tag_removal_blacklist)
                tag_removal_blacklist.update(tag.tag_classes())

            del self._resource_store[_resource_node.model.id]
            if _resource_node.model.data_id is not None:
                del self._resource_by_data_id_store[_resource_node.model.data_id]

        _delete_resource_helper(resource_node)
