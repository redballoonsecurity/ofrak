import dataclasses
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import (
    TypeVar,
    Set,
    Type,
    Dict,
    Optional,
    Iterable,
    MutableMapping,
    Union,
    Tuple,
    Sequence,
    List,
    Callable,
    Generic,
    Any,
    MutableSet,
    cast,
    overload,
)
from weakref import WeakValueDictionary

from sortedcontainers import SortedSet as _SortedSet

from ofrak.model.tag_model import ResourceTag
from ofrak_type.range import Range

T = TypeVar("T")
RT = TypeVar("RT", bound="ResourceTag")
RA = TypeVar("RA", bound="ResourceAttributes")
X = TypeVar("X", str, int, float, bytes)  # Indexable field types

_INDEXABLE_TYPES: Dict[str, Type] = {
    indexable_type.__name__: indexable_type
    for indexable_type in getattr(X, "__constraints__")  # type: ignore
}


class ResourceIndexedAttribute(Generic[X]):
    """
    Descriptor class for values in resource attributes which can be indexed. When a field `Foo`
    of a [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes] type `A` is indexed,
    it is possible to include an `r_filter` or `r_sort` in a query to the resource service which
    filters the returned resource by the value of `foo` each of them have.

    This class should not be explicitly instantiated, instead created using the @index decorator.

    For example:
    ```python
    @dataclass
    class A(ResourceAttributes):
        x: int

        @index
        def Foo(self) -> int:
            return self.x
    ```
    """

    def __init__(
        self,
        getter_func: Callable[[Any], X],
        nested_indexes: Iterable["ResourceIndexedAttribute"] = (),
    ):
        """
        :param getter_func: Getter function for the property
        :param nested_indexes: Additional index types that are required to calculate the value
        of this index

        :raises TypeError: if the getter function does not have a return type annotation
        :raises TypeError: if the getter does not return an indexable type
        """
        _validate_indexed_type(getter_func)
        self.fget: Callable[[Any], X] = getter_func
        self.attributes_owner: Optional[Type[ResourceAttributes]] = None
        self.nested_indexes = nested_indexes
        self.index_name: str = getter_func.__name__

    def __set_name__(self, owner, name):
        self.attributes_owner = owner
        self.__name__ = f"{owner.__name__}.{name}"
        self.index_name = name

    @overload
    def __get__(self, instance: None, owner: type) -> "ResourceIndexedAttribute[X]":
        """
        Applicable when getting the ResourceIndexedAttribute of a class, not an instance.
        Example (continued building off of example from class docstring):
        A.X  # Returns a ResourceIndexedAttribute[int]
        """
        ...

    @overload
    def __get__(self, instance: Any, owner: type) -> X:
        """
        Applicable when getting the ResourceIndexedAttribute of an instance
        Example (continued building off of example from class docstring):
        a = A(10)
        a.X  # Returns 10
        """
        ...

    def __get__(self, instance: Any, owner: type) -> Union["ResourceIndexedAttribute[X]", X]:
        if instance is None:
            return self
        else:
            return self.fget(instance)

    def __getattr__(self, name) -> Any:
        ...

    def __set__(self, instance, value):
        raise ValueError("Cannot set value of indexed attributes")

    def get_value(
        self,
        index_holder: "ResourceModel",
    ) -> Optional[X]:
        if self.attributes_owner is None:
            raise TypeError(
                f"Cannot get index value for {self.__name__} of model "
                f"{index_holder.id.hex()} because {self.__name__}'s owner has not "
                f"been set. This cannot happen unless `get_index` has somehow been "
                f"called during class creation, before the owner is set."
            )
        else:
            attributes = index_holder.get_attributes(self.attributes_owner)
            if attributes is None:
                return None
            elif self.nested_indexes:
                # Create new copy of attributes to inject index values into
                attributes_plus_required_indexes = dataclasses.replace(attributes)
                for nested_index in self.nested_indexes:
                    val = nested_index.get_value(index_holder)
                    if val is None:
                        # Not all of the nested indexes are available, can't calculate index val.
                        return None
                    object.__setattr__(
                        attributes_plus_required_indexes, nested_index.index_name, val
                    )
                return self.fget(attributes_plus_required_indexes)
            else:
                return self.fget(attributes)

    def __repr__(self) -> str:
        return self.__name__


@overload
def index(
    *,
    nested_indexes: Iterable[ResourceIndexedAttribute] = ...,
) -> Callable[[Callable[[Any], X]], ResourceIndexedAttribute[X]]:
    """
    When called as:

    @index(nested_indexes=(...))
    def MyIndex(self):
        ...
    """
    ...


@overload
def index(
    index_value_getter: Callable[[Any], X],
) -> ResourceIndexedAttribute[X]:
    """
    When called as:

    @index
    def MyIndex(self):
        ...
    """
    ...


def index(
    index_value_getter: Callable[[Any], X] = None,
    *,
    nested_indexes: Iterable[ResourceIndexedAttribute] = (),
) -> Union[
    Callable[[Callable[[Any], X]], ResourceIndexedAttribute[X]], ResourceIndexedAttribute[X]
]:
    """
    Create a new indexable attribute for a
    [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes].

    :param index_value_getter: Method of
        [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes] which returns the
        value of the index for that instance.
    :param nested_indexes: Additional index types that are required to calculate the value
    of this index.

    :return: [ResourceIndexedAttribute][ofrak.model.resource_model.ResourceIndexedAttribute]
        instance
    """
    # See if we're being called as @index or @index().
    if index_value_getter is None:
        # We're called with parens.
        def wrap(_index_value_getter) -> ResourceIndexedAttribute[X]:
            return ResourceIndexedAttribute[X](_index_value_getter, nested_indexes)

        return wrap  # type: ignore

    # We're called as @index without parens.
    return ResourceIndexedAttribute[X](index_value_getter)


class ResourceAttributes:
    DATACLASS_PARAMS = {"frozen": True, "eq": True}

    """
    Wraps immutable attributes attached to a resource. While not enforced programmatically, only
    analyzers should add/replace attributes attached to a resource. Additionally, a
    [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes] instance also defines
    which component attached the attributes to a specific resource.
    """

    def __str__(self):
        fields_str = ", ".join(
            f"{field.name}={str(getattr(self, field.name))}" for field in dataclasses.fields(self)
        )
        return f"{self.__class__.__name__}({fields_str})"

    @classmethod
    def get_indexable_attributes(cls) -> List[ResourceIndexedAttribute]:
        indexable_attributes = []
        for name, attr in cls.__dict__.items():
            if type(attr) is ResourceIndexedAttribute:
                indexable_attributes.append(attr)
        return indexable_attributes

    @staticmethod
    def replace_updated(
        resource_attributes: "ResourceAttributes", updated_attributes: Any
    ) -> "ResourceAttributes":
        """
        Replace the fields of `resource_attributes` with the updated values found in
        `updated_attributes`, returning a new object. The fields having non-`None` values in
        `updated_attributes` are considered to be updated and will be replaced in
        `resource_attributes` if they exist there.

        Both arguments must be `dataclass` instances.

        `updated_attributes` is typically a descendant of
        [ComponentConfig][ofrak.model.component_model.ComponentConfig].

        !!! todo "To do"

               This currently assumes that values can't be updated to `None`, but that could happen.

        :raises TypeError: if any of `resource_attributes` or `updated_attributes` isn't a
            dataclass instance.
        """
        for obj in (resource_attributes, updated_attributes):
            if not (dataclasses.is_dataclass(obj) and not isinstance(obj, type)):
                raise TypeError(f"{obj.__name__} must be a dataclass instance")
        updated_fields = {
            field: val
            for field, val in dataclasses.asdict(updated_attributes).items()
            if val is not None
        }
        updated_attributes = dataclasses.replace(
            resource_attributes,
            **updated_fields,
        )
        return updated_attributes


class ResourceAttributeDependency:
    dependent_resource_id: bytes
    component_id: bytes
    attributes: Type[ResourceAttributes]

    __slots__ = ("dependent_resource_id", "component_id", "attributes")

    def __init__(
        self,
        dependent_resource_id: bytes,
        component_id: bytes,
        attributes: Type[ResourceAttributes],
    ):
        """
        Create a dependency that says the resource ``dependent_resource_id`` has some attributes
        ``attributes`` (added by ``component_id``) which depend on some information in another
        resource. That information is either a range of the data or some attributes of that other
        resource.

        :param dependent_resource_id: ID of the resource which has a dependency
        :param component_id: Type of attributes on the resource which has a dependency
        :param attributes: Component which ran on the resource to create the attributes
        """
        self.dependent_resource_id = dependent_resource_id
        self.component_id = component_id
        self.attributes = attributes

    def __hash__(self):
        return hash((self.dependent_resource_id, self.component_id, self.attributes))

    def __eq__(self, other):
        if not isinstance(other, ResourceAttributeDependency):
            return False
        return (
            self.dependent_resource_id == other.dependent_resource_id
            and self.component_id == other.component_id
            and self.attributes == other.attributes
        )


class SortedSet(_SortedSet, MutableSet[T], Sequence[T]):
    """
    Typing shim for `sortedcollections.SortedSet` since it still has no type annotations.

    See <https://github.com/grantjenks/python-sortedcontainers/pull/136>.

    If we want to get rid of this, we either stop using `SortedSet`, complete that PR and get it
    accepted, or wait for someone else to.
    """

    def __init__(
        self, iterable: Optional[Iterable[T]] = None, key: Optional[Callable[[T], Any]] = None
    ):
        super().__init__(iterable, key)


ModelIdType = bytes
ModelDataIdType = Optional[bytes]
ModelParentIdType = Optional[bytes]
ModelTagsType = SortedSet[ResourceTag]
ModelAttributesType = Dict[Type[RA], RA]
ModelDataDependenciesType = Dict[ResourceAttributeDependency, Set[Range]]
ModelAttributeDependenciesType = Dict[Type[ResourceAttributes], Set[ResourceAttributeDependency]]
ModelComponentVersionsType = Dict[bytes, int]
ModelComponentsByAttributesType = Dict[Type[ResourceAttributes], Tuple[bytes, int]]


class ResourceModel:
    """
    :param ModelIdType id:
    :param ModelDataIdType data_id:
    :param ModelParentIdType parent_id:
    :param Optional[Sequence[ResourceTag]] tags:
    :param Optional[ModelAttributesType] attributes:
    :param Optional[ModelAttributesType] data_dependencies: Stores the dependencies of other
        resources on specific data ranges within this resource
    :param Optional[ModelAttributeDependenciesType] attribute_dependencies: Stores the dependencies
        of other resources on [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes]
        of this resource
    :param Optional[ModelComponentVersionsType] component_versions: Stores the version of
        [ComponentInterface][ofrak.component.interface.ComponentInterface] which has been run on
        this resource
    :param Optional[ModelComponentsByAttributesType] components_by_attributes: For each
        [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes], stores the id of the
        [ComponentInterface][ofrak.component.interface.ComponentInterface] which was run to
        create it
    """

    id: ModelIdType
    data_id: ModelDataIdType
    parent_id: ModelParentIdType
    tags: ModelTagsType
    attributes: ModelAttributesType
    data_dependencies: ModelDataDependenciesType
    attribute_dependencies: ModelAttributeDependenciesType
    component_versions: ModelComponentVersionsType
    components_by_attributes: ModelComponentsByAttributesType

    __slots__ = (
        "id",
        "data_id",
        "parent_id",
        "tags",
        "attributes",
        "data_dependencies",
        "attribute_dependencies",
        "component_versions",
        "components_by_attributes",
        "__weakref__",  # Required to get a weak ref to an instance
    )

    def __init__(
        self,
        id: ModelIdType,
        data_id: ModelDataIdType = None,
        parent_id: ModelParentIdType = None,
        tags: Optional[Sequence[ResourceTag]] = None,
        attributes: Optional[ModelAttributesType] = None,
        data_dependencies: Optional[ModelDataDependenciesType] = None,
        attribute_dependencies: Optional[ModelAttributeDependenciesType] = None,
        component_versions: Optional[ModelComponentVersionsType] = None,
        components_by_attributes: Optional[ModelComponentsByAttributesType] = None,
    ):
        attributes = attributes or {}
        data_dependencies = defaultdict(set, data_dependencies or {})
        attribute_dependencies = defaultdict(set, attribute_dependencies or {})
        component_versions = component_versions or {}
        components_by_attributes = components_by_attributes or {}

        self.id: ModelIdType = id
        self.data_id: ModelDataIdType = data_id
        self.parent_id: ModelParentIdType = parent_id
        self.tags: ModelTagsType = SortedSet(tags or (), key=lambda t: t.tag_specificity())
        self.attributes: ModelAttributesType = attributes
        self.data_dependencies: ModelDataDependenciesType = data_dependencies
        self.attribute_dependencies: ModelAttributeDependenciesType = attribute_dependencies
        self.component_versions: ModelComponentVersionsType = component_versions
        self.components_by_attributes: ModelComponentsByAttributesType = components_by_attributes

    @staticmethod
    def _clone_dependencies(
        dependencies: ModelAttributeDependenciesType,
    ) -> ModelAttributeDependenciesType:
        new_dependencies: ModelAttributeDependenciesType = defaultdict(set)
        new_dependencies.update(
            {attribute: set(dependencies) for attribute, dependencies in dependencies.items()}
        )
        return new_dependencies

    @staticmethod
    def _clone_data_dependencies(
        dependencies: Dict[ResourceAttributeDependency, Set[Range]]
    ) -> Dict[ResourceAttributeDependency, Set[Range]]:
        new_dependencies = defaultdict(set)
        for dependency, ranges in dependencies.items():
            new_dependencies[dependency] = set(ranges)
        return new_dependencies

    def get_tags(self, inherit: bool = True) -> Sequence[ResourceTag]:
        if inherit is False:
            return self.tags
        tags = set()
        for _tag in self.tags:
            tags.update(_tag.tag_classes())
        return SortedSet(tags, key=lambda t: t.tag_specificity())

    def get_specific_tags(self, tag: RT) -> List[RT]:
        tags: List[RT] = []
        for _tag in self.tags:
            if issubclass(_tag, tag) and _tag is not tag:
                tags.append(cast(RT, _tag))

        return tags  # already guaranteed to be sorted

    def get_most_specific_tags(self) -> Iterable[ResourceTag]:
        tiered_tags = ResourceTag.sort_tags_into_tiers(self.tags)
        if len(tiered_tags) == 0:
            return ()
        tags_not_most_specific: Set[ResourceTag] = set()
        most_specific_tags = set()
        for tag_tier in reversed(tiered_tags):
            most_specific_tags_in_tier = set(tag_tier).difference(tags_not_most_specific)
            most_specific_tags.update(most_specific_tags_in_tier)
            for tag in tag_tier:
                tags_not_most_specific.update(set(cast(Iterable[ResourceTag], tag.__bases__)))

        return most_specific_tags

    @property
    def caption(self) -> str:
        captions = []
        for tag in self.get_most_specific_tags():
            captions.append(tag.caption(self.attributes))
        return ", ".join(captions)

    def has_tag(self, tag: ResourceTag, inherit: bool = True) -> bool:
        has_tag = tag in self.tags
        if has_tag or inherit is False:
            return has_tag
        for _tag in self.tags:
            if tag in _tag.tag_classes():
                return True
        return False

    def get_attributes(self, attributes_type: Type[RA]) -> Optional[RA]:
        return self.attributes.get(attributes_type, None)

    def get_index_values(self) -> Dict[ResourceIndexedAttribute[X], X]:
        indexable_values = dict()
        for attributes in self.attributes.values():
            for indexable_attribute in attributes.get_indexable_attributes():
                indexable_values[indexable_attribute] = indexable_attribute.get_value(self)
        return indexable_values

    def get_index_values_depending_on_indexes(
        self, other_indexes: Iterable[ResourceIndexedAttribute]
    ) -> Dict[ResourceIndexedAttribute[X], Optional[X]]:
        indexable_values: Dict[ResourceIndexedAttribute[X], Optional[X]] = dict()
        next_indexes_to_search_for: Set[ResourceIndexedAttribute[X]] = set(other_indexes)
        all_indexable_attributes_with_nested: Set[ResourceIndexedAttribute[X]] = set()
        for attributes in self.attributes.values():
            all_indexable_attributes_with_nested.update(
                indexable_attr
                for indexable_attr in attributes.get_indexable_attributes()
                if indexable_attr.nested_indexes
            )

        while len(next_indexes_to_search_for) > 0:
            index_nesting_search_space = next_indexes_to_search_for
            next_indexes_to_search_for = set()
            for indexable_attr in all_indexable_attributes_with_nested:
                if any(
                    nested_index in index_nesting_search_space
                    for nested_index in indexable_attr.nested_indexes
                ):
                    next_indexes_to_search_for.add(indexable_attr)
                    indexable_values[indexable_attr] = indexable_attr.get_value(self)

        return indexable_values

    def has_attributes(self, attributes_type: Type[ResourceAttributes]) -> bool:
        return attributes_type in self.attributes

    def get_component_id_by_attributes(
        self, attributes: Type[ResourceAttributes]
    ) -> Optional[bytes]:
        component = self.components_by_attributes.get(attributes)
        if component is not None:
            component_id, _ = component
            return component_id
        return None

    def get_component_version(self, component_id: bytes) -> Optional[int]:
        return self.component_versions.get(component_id)

    def clone(self):
        return ResourceModel(
            self.id,
            self.data_id,
            self.parent_id,
            self.tags,
            dict(self.attributes),
            ResourceModel._clone_data_dependencies(self.data_dependencies),
            ResourceModel._clone_dependencies(self.attribute_dependencies),
            dict(self.component_versions),
            dict(self.components_by_attributes),
        )

    @staticmethod
    def create(
        id: bytes,
        data_id: Optional[bytes] = None,
        parent_id: Optional[bytes] = None,
        tags: Iterable[ResourceTag] = None,
        attributes: Iterable[ResourceAttributes] = None,
        created_by_component_id: bytes = None,
        created_by_component_version: int = None,
    ) -> "ResourceModel":
        attributes_dict = dict()
        components_by_attributes = dict()
        if attributes is not None:
            for _attributes in attributes:
                attributes_dict[type(_attributes)] = _attributes
                if created_by_component_id is not None and created_by_component_version is not None:
                    components_by_attributes[type(_attributes)] = (
                        created_by_component_id,
                        created_by_component_version,
                    )
        components_by_version: ModelComponentVersionsType = dict()

        final_tags: Set[ResourceTag] = set()

        if tags is not None:
            final_tags.update(tags)
            _tags_to_process = list(tags)

            while len(_tags_to_process) > 0:
                t = _tags_to_process.pop()
                for base_tag in t.base_tags():
                    if base_tag not in final_tags:
                        final_tags.add(base_tag)
                        _tags_to_process.append(base_tag)
        return ResourceModel(
            id,
            data_id,
            parent_id,
            SortedSet(final_tags, key=lambda t: t.tag_specificity()),
            attributes_dict,
            components_by_attributes=components_by_attributes,
            component_versions=components_by_version,
        )

    def __eq__(self, other):
        if not isinstance(other, ResourceModel):
            return False

        return all(
            [
                self.id == other.id,
                self.data_id == other.data_id,
                self.parent_id == other.parent_id,
                self.tags == other.tags,
                self.attributes == other.attributes,
                self.data_dependencies == other.data_dependencies,
                self.attribute_dependencies == other.attribute_dependencies,
                self.component_versions == other.component_versions,
                self.components_by_attributes == other.components_by_attributes,
            ]
        )


# NOTE: in Python >= 3.10, @dataclass(slots=True) can be used to make this class definition smaller.
class ResourceModelDiff:
    id: bytes
    tags_added: Set[ResourceTag]
    tags_removed: Set[ResourceTag]
    attributes_added: Dict[Type[ResourceAttributes], ResourceAttributes]
    attributes_removed: Set[Type[ResourceAttributes]]
    data_dependencies_added: Set[Tuple[ResourceAttributeDependency, Range]]
    data_dependencies_removed: Set[ResourceAttributeDependency]
    attribute_dependencies_added: Set[Tuple[Type[ResourceAttributes], ResourceAttributeDependency]]
    attribute_dependencies_removed: Set[
        Tuple[Type[ResourceAttributes], ResourceAttributeDependency]
    ]
    component_versions_added: Set[Tuple[bytes, int]]
    component_versions_removed: Set[bytes]
    attributes_component_added: Set[Tuple[Type[ResourceAttributes], bytes, int]]
    attributes_component_removed: Set[Type[ResourceAttributes]]

    __slots__ = (
        "id",
        "tags_added",
        "tags_removed",
        "attributes_added",
        "attributes_removed",
        "data_dependencies_added",
        "data_dependencies_removed",
        "attribute_dependencies_added",
        "attribute_dependencies_removed",
        "component_versions_added",
        "component_versions_removed",
        "attributes_component_added",
        "attributes_component_removed",
    )

    def __init__(
        self,
        id: bytes,
        tags_added: Optional[Set[ResourceTag]] = None,
        tags_removed: Optional[Set[ResourceTag]] = None,
        attributes_added: Optional[Dict[Type[ResourceAttributes], ResourceAttributes]] = None,
        attributes_removed: Optional[Set[Type[ResourceAttributes]]] = None,
        data_dependencies_added: Optional[Set[Tuple[ResourceAttributeDependency, Range]]] = None,
        data_dependencies_removed: Optional[Set[ResourceAttributeDependency]] = None,
        attribute_dependencies_added: Optional[
            Set[Tuple[Type[ResourceAttributes], ResourceAttributeDependency]]
        ] = None,
        attribute_dependencies_removed: Optional[
            Set[Tuple[Type[ResourceAttributes], ResourceAttributeDependency]]
        ] = None,
        component_versions_added: Optional[Set[Tuple[bytes, int]]] = None,
        component_versions_removed: Optional[Set[bytes]] = None,
        attributes_component_added: Optional[
            Set[Tuple[Type[ResourceAttributes], bytes, int]]
        ] = None,
        attributes_component_removed: Optional[Set[Type[ResourceAttributes]]] = None,
    ):
        self.id = id
        self.tags_added: Set[ResourceTag] = tags_added or set()
        self.tags_removed: Set[ResourceTag] = tags_removed or set()
        self.attributes_added: Dict[Type[ResourceAttributes], ResourceAttributes] = (
            attributes_added or {}
        )
        self.attributes_removed: Set[Type[ResourceAttributes]] = attributes_removed or set()
        self.data_dependencies_added: Set[Tuple[ResourceAttributeDependency, Range]] = (
            data_dependencies_added or set()
        )
        self.data_dependencies_removed: Set[ResourceAttributeDependency] = (
            data_dependencies_removed or set()
        )
        self.attribute_dependencies_added: Set[
            Tuple[Type[ResourceAttributes], ResourceAttributeDependency]
        ] = (attribute_dependencies_added or set())
        self.attribute_dependencies_removed = attribute_dependencies_removed or set()
        self.component_versions_added = component_versions_added or set()
        self.component_versions_removed = component_versions_removed or set()
        self.attributes_component_added = attributes_component_added or set()
        self.attributes_component_removed = attributes_component_removed or set()

    def apply(self, model: ResourceModel) -> ResourceModel:
        # TODO: Raise exceptions if trying to add stuff that already exist or remove stuff that
        #  doesn't
        updated_model = model.clone()
        updated_model.tags.update(self.tags_added)
        updated_model.tags.difference_update(self.tags_removed)

        for attributes_type_removed in self.attributes_removed:
            del updated_model.attributes[attributes_type_removed]
        for type_attributes_added, attributes_added in self.attributes_added.items():
            updated_model.attributes[type_attributes_added] = attributes_added

        for data_dependency in self.data_dependencies_removed:
            del updated_model.data_dependencies[data_dependency]
        for data_dependency, data_range in self.data_dependencies_added:
            updated_model.data_dependencies[data_dependency].add(data_range)

        for attribute_type, attribute_dependency in self.attribute_dependencies_removed:
            if attribute_dependency in updated_model.attribute_dependencies[attribute_type]:
                updated_model.attribute_dependencies[attribute_type].remove(attribute_dependency)
        for attribute_type, attribute_dependency in self.attribute_dependencies_added:
            updated_model.attribute_dependencies[attribute_type].add(attribute_dependency)

        for component_id in self.component_versions_removed:
            del updated_model.component_versions[component_id]
        for component_id, component_version in self.component_versions_added:
            updated_model.component_versions[component_id] = component_version

        for attribute_type in self.attributes_component_removed:
            if updated_model.get_component_id_by_attributes(attribute_type) is not None:
                del updated_model.components_by_attributes[attribute_type]
        for attribute_type, component_id, version in self.attributes_component_added:
            updated_model.components_by_attributes[attribute_type] = (component_id, version)

        return updated_model


class MutableResourceModel(ResourceModel):
    __slots__ = "is_modified", "diff", "is_deleted"

    def __init__(
        self,
        id: bytes,
        data_id: Optional[bytes] = None,
        parent_id: Optional[bytes] = None,
        tags: Optional[Sequence[ResourceTag]] = None,
        attributes: Optional[Dict[Type[ResourceAttributes], ResourceAttributes]] = None,
        data_dependencies: Optional[Dict[ResourceAttributeDependency, Set[Range]]] = None,
        attribute_dependencies: Optional[
            Dict[Type[ResourceAttributes], Set[ResourceAttributeDependency]]
        ] = None,
        component_versions: Optional[Dict[bytes, int]] = None,
        components_by_attributes: Optional[ModelComponentsByAttributesType] = None,
    ):
        super().__init__(
            id,
            data_id,
            parent_id,
            tags,
            attributes,
            data_dependencies,
            attribute_dependencies,
            component_versions,
            components_by_attributes,
        )
        self.is_modified = False
        self.is_deleted = False
        self.diff = ResourceModelDiff(self.id)

    @staticmethod
    def from_model(model: ResourceModel):
        return MutableResourceModel(
            model.id,
            model.data_id,
            model.parent_id,
            model.tags,
            dict(model.attributes),
            ResourceModel._clone_data_dependencies(model.data_dependencies),
            ResourceModel._clone_dependencies(model.attribute_dependencies),
            dict(model.component_versions),
            dict(model.components_by_attributes),
        )

    def add_tag(self, tag: ResourceTag) -> Set[ResourceTag]:
        if tag in self.tags:
            return set()
        self.is_modified = True
        self.tags.add(tag)
        self.diff.tags_added.add(tag)
        new_tags = {tag}

        for base_tag in tag.base_tags():
            new_tags.update(self.add_tag(base_tag))

        return new_tags

    def remove_tag(self, tag: ResourceTag):
        self.is_modified = True
        self.tags.remove(tag)
        self.diff.tags_removed.add(tag)

    def add_attributes(self, attributes: ResourceAttributes):
        attributes_type = type(attributes)
        prev_attributes = self.attributes.get(attributes_type)
        if prev_attributes is not None:
            if prev_attributes == attributes:
                return
            else:
                self.diff.attributes_removed.add(attributes_type)
        self.is_modified = True
        self.attributes[attributes_type] = attributes
        self.diff.attributes_added[attributes_type] = attributes

    def remove_attributes(self, attributes_type: Type[ResourceAttributes]):
        self.is_modified = True
        del self.attributes[attributes_type]
        self.diff.attributes_removed.add(attributes_type)

    def add_attribute_dependency(
        self, attribute_type: Type[ResourceAttributes], dependency: ResourceAttributeDependency
    ):
        self.is_modified = True
        self.attribute_dependencies[attribute_type].add(dependency)
        self.diff.attribute_dependencies_added.add((attribute_type, dependency))

    def add_data_dependency(self, dependency: ResourceAttributeDependency, data_range: Range):
        self.is_modified = True
        self.data_dependencies[dependency].add(data_range)
        self.diff.data_dependencies_added.add((dependency, data_range))

    def remove_dependency(self, dependency: ResourceAttributeDependency):
        if dependency in self.data_dependencies:
            self.is_modified = True
            del self.data_dependencies[dependency]
            self.diff.data_dependencies_removed.add(dependency)
        for attribute_type, attribute_dependencies in self.attribute_dependencies.items():
            if dependency in attribute_dependencies:
                self.is_modified = True
                attribute_dependencies.remove(dependency)
                self.diff.attribute_dependencies_removed.add((attribute_type, dependency))

    def add_component(
        self,
        component_id: bytes,
        version: int,
    ):
        """
        Mark that a component has run on a resource.
        """
        self.is_modified = True
        self.component_versions[component_id] = version
        self.diff.component_versions_added.add((component_id, version))

    def add_component_for_attributes(
        self,
        component_id: bytes,
        version: int,
        attribute_type: Type[ResourceAttributes],
    ):
        """
        Mark that a component has added attributes to a resource
        """
        self.components_by_attributes[attribute_type] = (component_id, version)
        self.diff.attributes_component_added.add((attribute_type, component_id, version))

    def remove_component(
        self, component_id: bytes, attribute_type: Optional[Type[ResourceAttributes]]
    ):
        if component_id in self.component_versions:
            self.is_modified = True
            del self.component_versions[component_id]
            self.diff.component_versions_removed.add(component_id)
        if attribute_type in self.components_by_attributes:
            self.is_modified = True
            del self.components_by_attributes[attribute_type]
            self.diff.attributes_component_removed.add(attribute_type)

    def reset(self, model: ResourceModel):
        self.id = model.id
        self.data_id = model.data_id
        self.parent_id = model.parent_id
        self.tags = SortedSet(model.tags, key=lambda t: t.tag_specificity())
        self.attributes = dict(model.attributes)
        self.data_dependencies: Dict[
            ResourceAttributeDependency, Set[Range]
        ] = ResourceModel._clone_data_dependencies(model.data_dependencies)
        self.attribute_dependencies: ModelAttributeDependenciesType = (
            ResourceModel._clone_dependencies(model.attribute_dependencies)
        )
        self.component_versions = dict(model.component_versions)
        self.components_by_attributes = dict(model.components_by_attributes)
        self.is_modified = False
        self.diff = ResourceModelDiff(self.id)

    def save(self):
        self.is_modified = False
        diff = self.diff
        self.diff = ResourceModelDiff(self.id)
        return diff

    def to_diff(self):
        return self.diff

    def to_model(self):
        return super().clone()


class ResourceContext(ABC):
    """
    Resource context.
    """

    def __init__(self, resource_models: MutableMapping[bytes, MutableResourceModel]):
        self.resource_models = resource_models


class ResourceContextFactory(ABC):
    @abstractmethod
    def create(self) -> ResourceContext:
        pass


class EphemeralResourceContext(ResourceContext):
    def __init__(self):
        super().__init__(dict())


class EphemeralResourceContextFactory(ResourceContextFactory):
    def create(self) -> EphemeralResourceContext:
        return EphemeralResourceContext()


class ClientResourceContext(ResourceContext):
    def __init__(self):
        super().__init__(WeakValueDictionary())


class ClientResourceContextFactory(ResourceContextFactory):
    def create(self) -> ClientResourceContext:
        return ClientResourceContext()


def _validate_indexed_type(getter_func: Callable[[Any], X]):
    """
    Verify the getter function returns a valid indexable type - a primitive type which can be
    compared.

    :param getter_func:

    :raises TypeError: if the getter function does not have a return type annotation
    :raises TypeError: if the getter does not return an indexable type
    :return:
    """

    if not hasattr(getter_func, "__annotations__"):
        raise TypeError(
            f"Index {getter_func.__name__} must have type annotations, including return type"
        )
    annotations = getattr(getter_func, "__annotations__")
    if "return" not in annotations:
        raise TypeError(
            f"Index {getter_func.__name__} must have type annotations, including return type"
        )
    index_type = annotations["return"]
    if type(index_type) is str:
        # handles case where type annotations is "stringified" and not the actual type, e.g.
        # def foo(self) -> "int": ...
        index_type_name = index_type
    else:
        index_type_name = index_type.__name__

    if index_type_name not in _INDEXABLE_TYPES:
        raise TypeError(
            f"Type of index {getter_func.__name__} is {index_type}, which is not "
            f"one of {_INDEXABLE_TYPES.values()}; cannot index by this value!"
        )


# MyPy does not yet support cyclic types (https://stackoverflow.com/a/58383852), so the input type
# annotation must be more general than the actual type is
def _get_leaves(tree: Dict) -> Iterable[ResourceTag]:
    result = []
    for cls, children in tree.items():
        if children is None:
            result.append(cls)
        else:
            result.extend(_get_leaves(children))
    return result
