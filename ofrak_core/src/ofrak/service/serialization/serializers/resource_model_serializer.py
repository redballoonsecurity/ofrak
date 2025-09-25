from typing import Dict, Type, Sequence, Any

from ofrak import ResourceTag
from ofrak.model.resource_model import ResourceModel, ResourceAttributes
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class ResourceModelSerializer(SerializerInterface):
    """
    Serialize and deserialize `ResourceModel` into `PJSONType`.

    There are two issues with ResourceModel:
    1) the type hint of ResourceModel.attributes = Dict[Type[RA], RA] with
    RA = TypeVar("RA", bound="ResourceAttributes")
    This is used to refer to ResourceAttributes in the type hints without creating circular imports.
    But the serializer needs to know the real class ResourceAttributes, not just its name.
    2) the type hint of ResourceModel.tags is SortedSet[ResourceTag], but the generic serializer doesn't know how to
    handle SortedSet (to do it right, we would also need to serialize the sorting function, not just the sequence).
    But tags can be given to ResourceModel.__init__ as simply any Sequence, so we use that type hint instead.
    """

    targets = (ResourceModel,)

    # Start from the type hints of ResourceModel, but modify them for attributes and tags
    usable_type_hints = ResourceModel.__annotations__
    usable_type_hints["attributes"] = Dict[Type[ResourceAttributes], ResourceAttributes]
    usable_type_hints["tags"] = Sequence[ResourceTag]

    def obj_to_pjson(self, obj: Any, _type_hint: Any) -> Dict[str, PJSONType]:
        result = {}
        for attr_name, type_hint in self.usable_type_hints.items():
            result[attr_name] = self._service.to_pjson(getattr(obj, attr_name), type_hint)

        # Manually add captions to the generated dictionary since they are a read-only property,
        # and they should only be serialized, never deserialized and passed to an object's __init__
        result["caption"] = obj.caption

        return result

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], _type_hint: Any) -> Any:
        deserialized_attrs = {
            attr_name: self._service.from_pjson(pjson_obj[attr_name], type_hint)
            for attr_name, type_hint in self.usable_type_hints.items()
        }
        return ResourceModel(**deserialized_attrs)
