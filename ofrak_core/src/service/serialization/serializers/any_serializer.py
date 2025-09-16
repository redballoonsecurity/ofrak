from typing import Any

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class AnySerializer(SerializerInterface):
    """
    Serialize and deserialize objects with type hint `Any` into `PJSONType`.

    Implementation: a simple and conservative design in which the object is only serialized
    if it's already of `PJSONType` (the check is performed by beartype and the method signatures).
    """

    targets = (Any,)  # type: ignore

    def obj_to_pjson(self, obj: PJSONType, _type_hint: Any) -> PJSONType:
        return obj

    def pjson_to_obj(self, pjson_obj: PJSONType, _type_hint: Any) -> PJSONType:
        return pjson_obj
