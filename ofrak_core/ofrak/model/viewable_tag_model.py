import dataclasses
from _warnings import warn
from collections import defaultdict
from dataclasses import dataclass
from typing import Tuple, Type, Dict, Any, List, Set, TypeVar, Iterable, MutableMapping
from weakref import WeakValueDictionary

import ofrak.model._auto_attributes
from ofrak.model.resource_model import ResourceAttributes, ResourceIndexedAttribute, ResourceModel
from ofrak.model.tag_model import ResourceTag

_VIEW_ATTRIBUTES_TYPE = "__view_attributes_type__"
_COMPOSED_ATTRIBUTES_TYPE = "__composed_attributes_types__"
_VIEW_ATTRIBUTE_TYPE_NAME_SUFFIX = "AutoAttributes"


RA = TypeVar("RA", bound=ResourceAttributes)
RVI = TypeVar("RVI", bound="ResourceViewInterface")


@dataclass
class _NoResourceAttributesType(ResourceAttributes):
    """
    Dummy class indicating a
    [ViewableResourceTag][ofrak.model.viewable_tag_model.ViewableResourceTag] has no
    `attributes_type` attribute.
    """


_NO_RESOURCE_ATTRIBUTES_TYPE = _NoResourceAttributesType


class ViewableResourceTag(ResourceTag):
    def __new__(mcs, name: str, bases: Tuple[Type, ...], namespace: Dict[str, Any]):
        """
        Create a new attributes type for the `ViewableResourceTag` which is about to be created.
        This type will inherit from `ResourceAttributes` and have fields corresponding to all the
        fields of unique to the new `ViewableResourceTag`. This type, as well as all attributes
        types inherited from the bases, are added to the namespace of the new class under the
        dunders `_VIEW_ATTRIBUTES_TYPE` and `_COMPOSED_ATTRIBUTES_TYPE`.

        This method also checks for possible attempted polymorphism, raising warnings if any
        method overrides are detected.

        The `__new__` method can inspect and edit the names, bases, and namespace (attributes and
        methods) of the class. It is called after the class definition has been parsed, and before
        the new class object has been created.

        :param name: Name of the new class
        :param bases: Base classes of the new class
        :param namespace: Namespace of attributes for the new class, in the form of a dictionary
        mapping attribute names to objects
        :return:
        """
        _check_for_polymorphism(name, bases, namespace)
        attributes_type = mcs._create_attributes_type(name, bases, namespace)
        composed_attributes_types = [attributes_type]
        for base_cls in bases:
            composed_attributes_types.extend(_get_attributes_types_recursively(base_cls))
        composed_attributes_types = _filter_attributes_types(composed_attributes_types)

        namespace[_VIEW_ATTRIBUTES_TYPE] = attributes_type
        namespace[_COMPOSED_ATTRIBUTES_TYPE] = composed_attributes_types
        return super().__new__(mcs, name, bases, namespace)

    def __init__(cls, name: str, bases: Tuple[Type, ...], namespace: Dict[str, Any]):
        """
        Fix up any `@index` defined in this `ViewableResourceTag`. Each index descriptor needs an
        owner which is a `ResourceAttributes` subclass, and an automatically populated owner will be
        set to the newly created `cls`, which is an instance of `ViewableResourceTag` and not a
        `ResourceAttributes` subclass. This is a little hacky, but it works just fine.

        Can inspect and edit the names, bases, and namespace (attributes and methods) of the class.

        Called after the new class object has been created.

        :param name: Name of the new class
        :param bases: Base classes of the new class
        :param namespace: Namespace of attributes for the new class, in the form of a dictionary
        mapping attribute names to objects

        :raises TypeError: If the viewable tag has no attributes but does have an @index

        :return:
        """
        # Change owner of the indexes to be the attributes type
        for name, index_descriptor in _get_indexes(namespace).items():
            if cls.attributes_type is None:
                raise TypeError(
                    f"Cannot have an index in a ResourceView which has no attributes "
                    f"- an index should only access one set of attributes, "
                    f"so this index is likely illegal anyway."
                )
            index_descriptor.__set_name__(cls.attributes_type, name)

        super().__init__(cls, name, bases)  # type: ignore

    @property
    def attributes_type(cls) -> Type[ResourceAttributes]:
        """
        Get the auto-generated `ResourceAttributes` subclass for this `ViewableResourceTag`. The
        returned class is a `dataclass` which encapsulates the fields defined in one specific
        `ViewableResourceTag`. For example if `B` inherits from `A` and `A` defines several fields,
        `B.attributes_type` has only fields defined in `B`, and none of the fields defined in `A`.

        :return: The auto-generated `ResourceAttributes` subclass for this `ViewableResourceTag`
        class, in no particular order.
        """
        return getattr(cls, _VIEW_ATTRIBUTES_TYPE)

    @property
    def composed_attributes_types(cls) -> Iterable[Type[ResourceAttributes]]:
        """
        Get all of the `ResourceAttributes` subclasses which this class is composed of. This means
        walking back through the class hierarchy and getting the `base.attributes_type` for every
        base class of this class.

        :return: The `attributes_type` of every `ViewableResourceTag` this class inherits from,
        in no particular order.
        """
        return getattr(cls, _COMPOSED_ATTRIBUTES_TYPE)

    @classmethod
    def _create_attributes_type(
        mcs, name: str, bases: Tuple[Type, ...], namespace: Dict[str, Any]
    ) -> Type[ResourceAttributes]:
        """
        Get a type inheriting from `ResourceAttributes` which is unique to this tag (`cls`).
        :return:
        """

        # First make this a dataclass to easily get its fields
        # We can't depend on the class already being a dataclass because class decorators run
        # after metaclass __new__ and __init__ methods, so it is not yet a dataclass
        tmp_cls = super().__new__(mcs, name, bases, namespace)
        tmp_dataclass: object = dataclass(tmp_cls)  # type: ignore

        base_fields: Set[dataclasses.Field] = set()
        for base in bases:
            if type(base) is ViewableResourceTag:
                base_fields.update(dataclasses.fields(base))

        fields = [
            (_field.name, _field.type, _field)
            for _field in dataclasses.fields(tmp_dataclass)
            if _field not in base_fields and not _field.name.startswith("_")
        ]
        if len(fields) == 0:
            return _NO_RESOURCE_ATTRIBUTES_TYPE
        indexed_attributes_namespace = _get_indexes(namespace)
        # Creates a new class inheriting from ResourceAttributes, with the same fields as this
        # ViewableResourceTag, as well as the same indexed attribute descriptors
        attributes_type = dataclasses.make_dataclass(
            f"{name}{_VIEW_ATTRIBUTE_TYPE_NAME_SUFFIX}",
            fields,
            bases=(ResourceAttributes,),
            namespace=indexed_attributes_namespace,
            **ResourceAttributes.DATACLASS_PARAMS,
        )

        # By default, this new attributes_type is part of the "types" module.
        # Instead, we make it part of the module ofrak.model._auto_attributes.
        attributes_type.__module__ = "ofrak.model._auto_attributes"
        setattr(
            ofrak.model._auto_attributes,
            attributes_type.__name__,
            attributes_type,
        )

        return attributes_type


def _get_attributes_types_recursively(cls: type) -> List[Type[ResourceAttributes]]:
    if isinstance(cls, ViewableResourceTag):
        attrs_types = [cls.attributes_type]
        for base_cls in cls.__bases__:
            attrs_types.extend(_get_attributes_types_recursively(base_cls))
        return attrs_types
    else:
        return []


def _filter_attributes_types(
    attr_types: List[Type[ResourceAttributes]],
) -> List[Type[ResourceAttributes]]:
    filtered_types = set()
    for attr_type in attr_types:
        if attr_type is not _NO_RESOURCE_ATTRIBUTES_TYPE:
            filtered_types.add(attr_type)
    return list(filtered_types)


def _check_for_polymorphism(name: str, bases: Iterable[Type], namespace: Dict[str, Any]):
    """
    Check for any methods in a new class which override a parent's method. The behavior of
    `view_as` means that overriding methods might not work as users think it does. Calling
    something like `a = resource.view_as(A)` will always and only return instances of `A`. These
    resources may have tags `B` and/or `C` which inherit from `A` but the returned view is not an
    instance of `B` or `C`. Calling a method `a.foo()` on that resource will therefore **ALWAYS**
    dispatch to `A.foo`, never to `B.foo` or `C.foo`.

    This would break a design in which a user expects to only program against a common viewable
    tag's interface and let individual instances dispatch to some unique behavior. For example, if
    one gets all descendants with a common tag as a view of that tag, then calls a virtual method
    of those views, expecting each view to possibly do some unique behavior. Such a class hierarchy
    could be made to work, but we raise a warning to ensure that developers are conscious of this
    restriction and program accordingly.

    :param name: Name of the new class
    :param bases: Base classes of the new class
    :param namespace: Namespace of attributes for the new class, in the form of a dictionary
    mapping attribute names to objects
    """
    for base_cls in bases:
        # TODO: Figure out cleaner way to make an exception for ResourceView
        if name == "ResourceView":
            continue
        if isinstance(base_cls, ViewableResourceTag):
            parent_cls = base_cls

            parent_class_namespace = dir(parent_cls)

            common_attrs = set(namespace.keys()).intersection(set(parent_class_namespace))
            common_attrs = common_attrs.difference(dir(ViewableResourceTag))

            common_methods = {
                attr_name: namespace[attr_name]
                for attr_name in common_attrs
                if callable(namespace[attr_name])
            }

            overwritten_methods = {
                attr_name: attr
                for attr_name, attr in common_methods.items()
                if namespace[attr_name] != getattr(parent_cls, attr_name)
            }

            for method_name, method in overwritten_methods.items():
                warn(
                    f"{name}.{method_name} overrides the parent's method "
                    f"{method_name}; OFRAK Resources do not support runtime polymorphism, "
                    f"and this function may depend on runtime polymorphism."
                )


def _get_indexes(namespace: Dict[str, Any]) -> Dict[str, ResourceIndexedAttribute]:
    """
    Extract the index descriptors from a namespaces.
    """
    return {
        name: item for name, item in namespace.items() if isinstance(item, ResourceIndexedAttribute)
    }


@dataclass
class ResourceViewInterface(metaclass=ViewableResourceTag):
    def get_attributes_instances(self) -> Dict[Type[RA], RA]:
        raise NotImplementedError()

    def set_deleted(self):
        """
        Mark that the underlying resource has been deleted.
        :return:
        """
        raise NotImplementedError()

    @classmethod
    def create(cls: Type[RVI], resource_model: ResourceModel) -> RVI:
        raise NotImplementedError()


class ResourceViewContext:
    ViewByTag = MutableMapping[ViewableResourceTag, ResourceViewInterface]

    def __init__(self):
        self.views_by_resource: MutableMapping[bytes, ResourceViewContext.ViewByTag] = defaultdict(
            WeakValueDictionary
        )

    def has_view(self, resource_id: bytes, view_type: ViewableResourceTag) -> bool:
        return view_type in self.views_by_resource[resource_id]

    def get_view(self, resource_id: bytes, view_type: Type[RVI]) -> RVI:
        return self.views_by_resource[resource_id][view_type]  # type: ignore

    def add_view(self, resource_id: bytes, view: ResourceViewInterface):
        self.views_by_resource[resource_id][type(view)] = view
