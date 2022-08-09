import dataclasses
import functools
import logging
from dataclasses import dataclass
from typing import Optional, Type, TypeVar, Dict, Iterable, Any, cast, Set

from ofrak.resource import Resource

from ofrak.model.resource_model import ResourceAttributes, ResourceModel
from ofrak.model.tag_model import ResourceTag
from ofrak.model.viewable_tag_model import ResourceViewInterface

LOGGER = logging.getLogger(__file__)

RA = TypeVar("RA", bound=ResourceAttributes)
RV = TypeVar("RV", bound="ResourceView")


@dataclass
class ResourceView(ResourceViewInterface):
    """
    An object representing a resource, or a future resource. May contain attributes and methods.
    A class subclassing `ResourceView` is a [ResourceTag][ofrak.model.tag_model.ResourceTag] and
    resources can be tagged with that tag. All `ResourceView`s must be dataclasses. All fields of
    the class will be represented by a `ResourceAttributes` type, unless the field is private
    (leading '_' in name).

    A `ResourceView` offers a synchronous view of all of the expected attributes of a resource with
    a particular tag in one place.

    Modifying the fields of a view will not modify the attributes of the underlying resource, nor
    will modifying the attributes of the underlying resources automatically update the fields of an
    existing view. Instead, the underlying resource should be explicitly modified and then a new
    view should be created by calling `resource.view_as(...)` again.
    """

    _resource: Optional[Resource] = dataclasses.field(
        default=None, init=False, repr=False, compare=False
    )
    _deleted: bool = dataclasses.field(default=False, init=False, repr=False, compare=False)

    @classmethod
    def get_special_field_names(cls) -> Set[str]:
        return {"_resource", "_deleted"}

    @classmethod
    def caption(cls, attributes) -> str:
        return str(cls.__name__)

    @property
    def resource(self) -> Resource:
        """
        Getter to access the underlying resource.

        :raises ValueError: if there is no underlying resource

        :return: the underlying resource
        """
        if self._resource is None:
            if self._deleted:
                raise ValueError("Underlying resource was deleted!")
            else:
                raise ValueError(
                    "Cannot access ResourceView's resource because it has not been " "set!"
                )
        return self._resource

    @resource.setter
    def resource(self, res: Resource):
        """
        Setter to create the underlying resource.

        :param res: the resource which will be set as this view's underlying resource

        :raises ValueError: if there is already an underlying resource
        """
        if self._resource is not None:
            raise ValueError("Cannot set ResourceView's resource when it is already set!")

        self._resource = res

    def get_attributes_instances(self) -> Dict[Type[RA], RA]:
        """
        Create instances of `ResourceAttributes` for each of the composed attributes types of this
        view. Each field of this view will end up in exactly one of these instances. Each
        instance will have a different type.

        :return: A dictionary mapping from subclasses of `ResourceAttributes` to a single instance
        of each subclass.
        """
        attrs_instances = dict()
        for attrs_t in cast(Iterable[Type[RA]], type(self).composed_attributes_types):
            attrs_fields_dict = {
                field.name: getattr(self, field.name) for field in dataclasses.fields(attrs_t)
            }
            attributes_instance = attrs_t(**attrs_fields_dict)  # type: ignore
            attrs_instances[attrs_t] = attributes_instance

        return attrs_instances

    def set_deleted(self):
        self._resource = None
        self._deleted = True

    @classmethod
    @functools.lru_cache(None)
    def tag_specificity(cls) -> int:
        """
        Override [ResourceTag.tag_specificity][ofrak.model.tag_model.ResourceTag.tag_specificity]
        to indicate this is not a valid tag, but its subclasses will be.

        :return:
        """
        if cls is ResourceView or cls is ResourceViewInterface:
            return -1
        else:
            return ResourceTag.tag_specificity(cls)

    @classmethod
    def create(cls: Type[RV], resource_model: ResourceModel) -> RV:
        attributes_fields_values: Dict[str, Any] = dict()
        for required_attrs_type in cls.composed_attributes_types:
            if required_attrs_type not in resource_model.attributes:
                raise ValueError(
                    f"Required attributes type {required_attrs_type.__name__} not "
                    f"provided in {resource_model.attributes}"
                )
            attributes_instance = resource_model.attributes[required_attrs_type]
            try:
                dataclass_fields = dataclasses.fields(required_attrs_type)
            except TypeError as e:
                raise TypeError(
                    f"Could not get dataclass fields from {required_attrs_type.__name__} - is it a "
                    f"dataclass instance?"
                ) from e
            for field in dataclass_fields:
                attributes_fields_values[field.name] = getattr(attributes_instance, field.name)
        return cls(**attributes_fields_values)  # type: ignore
