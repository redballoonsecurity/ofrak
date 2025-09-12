from typing import Any

from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class BytesSerializer(SerializerInterface):
    """
    Serialize and deserialize bytes into `PJSONType`.

    Implementation: hex string.
    """

    targets = (bytes,)

    def obj_to_pjson(self, obj: bytes, _type_hint: Any) -> str:
        return obj.hex()

    def pjson_to_obj(self, pjson_obj: str, _type_hint: Any) -> bytes:
        return bytes.fromhex(pjson_obj)
