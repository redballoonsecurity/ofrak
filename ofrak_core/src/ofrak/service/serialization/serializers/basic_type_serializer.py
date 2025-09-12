from typing import Union, Any

from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class BasicTypeSerializer(SerializerInterface):
    """
    Serialize and deserialize basic types (which don't need any change) into `PJSONType`.
    """

    targets = (int, float, bool, str, type(None))

    BasicType = Union[int, float, bool, str, None]

    def obj_to_pjson(self, obj: BasicType, _type_hint: Any) -> BasicType:
        return obj

    def pjson_to_obj(self, pjson_obj: BasicType, _type_hint: Any) -> BasicType:
        return pjson_obj
