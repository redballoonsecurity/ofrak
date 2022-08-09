from typing import Type, Any

import inspect
import sys
from typing_inspect import get_origin

from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


def is_metaclass(type_hint):
    """Will recognize Type, Type[X], and metaclasses"""
    result = (
        type_hint == Type
        or get_origin(type_hint) == type
        or (inspect.isclass(type_hint) and issubclass(type_hint, type))
    )
    return result


class TypeSerializer(SerializerInterface):
    """
    Serialize and deserialize classes (not instances) into `PJSONType`

    Implementation: the module path and name of the class are encoded into a single string.
    """

    targets = (is_metaclass,)

    def obj_to_pjson(self, cls: Type, _type_hint: Any) -> str:
        module = inspect.getmodule(cls)
        if module is None:
            raise TypeError(f"Can't find the module where {cls} was defined")
        import_path = module.__name__
        cls_name = cls.__name__
        return f"{import_path}.{cls_name}"

    def pjson_to_obj(self, pjson_obj: str, _type_hint: Any) -> Type:
        module_path, cls_name = pjson_obj.rsplit(".", maxsplit=1)
        # To avoid executing arbitrary code, only allow deserialization from modules
        # which are already loaded.
        try:
            module = sys.modules[module_path]
        except KeyError:
            raise ValueError(f"Can't deserialize {pjson_obj}: module not already loaded")
        cls = getattr(module, cls_name)
        return cls
