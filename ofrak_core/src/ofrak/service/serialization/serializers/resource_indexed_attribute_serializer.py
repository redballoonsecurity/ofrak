from typing import Any, Type, Dict

from typing_inspect import get_origin

from ofrak.model.resource_model import ResourceIndexedAttribute, ResourceAttributes
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


def _is_generic_resource_indexed_attribute(type_hint):
    return get_origin(type_hint) == ResourceIndexedAttribute


class ResourceIndexedAttributeSerializer(SerializerInterface):
    """
    Serialize and deserialize `ResourceIndexedAttribute` and `ResourceIndexedAttribute[T]` into `PJSONType`.

    A ResourceIndexedAttributes instance can contain a Callable, which is hard to serialize.
    However, we can recover this ResourceIndexedAttributes instance if we know its
    attributes_owner and its name, both being easy to serialize.
    """

    targets = (ResourceIndexedAttribute, _is_generic_resource_indexed_attribute)

    def obj_to_pjson(self, obj: Any, type_hint: Any) -> Dict[str, PJSONType]:
        if obj.attributes_owner is None:
            raise TypeError(f"Cannot serialize {obj.__name__} because its owner has not been set.")
        else:
            return {
                "attributes_owner": self._service.to_pjson(
                    obj.attributes_owner, Type[ResourceAttributes]
                ),
                "name": obj.index_name,
            }

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], type_hint: Any) -> "ResourceIndexedAttribute":  # type: ignore
        attributes_owner = self._service.from_pjson(
            pjson_obj["attributes_owner"], Type[ResourceAttributes]
        )
        name = self._service.from_pjson(pjson_obj["name"], str)
        return getattr(attributes_owner, name)
