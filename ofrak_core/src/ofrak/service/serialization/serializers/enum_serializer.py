from enum import Enum
from typing import Any, Type

import inspect

from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


def is_enum(type_hint):
    return type_hint == Enum or (inspect.isclass(type_hint) and issubclass(type_hint, Enum))


class EnumSerializer(SerializerInterface):
    """
    Serialize and deserialize enum.Enum instances into `PJSONType`.

    Implementation: the class is serialized, along with the name of the attribute for this instance, into a string.
    """

    targets = (is_enum,)

    def obj_to_pjson(self, enum_instance: Enum, _type_hint: Any) -> str:
        return f"{self._service.to_pjson(enum_instance.__class__, Type)}.{enum_instance.name}"

    def pjson_to_obj(self, pjson_obj: str, _type_hint: Any) -> Enum:
        enum_cls_ref_pjson, enum_member_name = pjson_obj.rsplit(".", maxsplit=1)
        enum_cls = self._service.from_pjson(enum_cls_ref_pjson, Type)
        return enum_cls[enum_member_name]
