from dataclasses import is_dataclass, fields
from typing import Any, Dict, Type, cast, Tuple

import inspect

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.enum_serializer import is_enum
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface
from ofrak.service.serialization.serializers.type_serializer import is_metaclass


def _is_regular_class_instance(type_hint):
    return inspect.isclass(type_hint) and not is_enum(type_hint) and not is_metaclass(type_hint)


class ClassInstanceSerializer(SerializerInterface):
    """
    Serialize and deserialize class instances into `PJSONType`.

    Implementation: the class is serialized, along with the attributes of the instance taken from its annotations.
    In other words, the annotations determine the exact attributes of the instance which are serialized and then
    re-created during deserialization.

    Annotations are present in dataclasses by construction, but they need to be added for all the other classes
    if this default serializer is to process them correctly.

    Invoking __init__ and __post_init__ during deserialization could have side effects, though.

    For dataclasses, __init__ corresponds perfectly to the annotations, and the default assumption is that
    side effects in __post_init__ are desirable to re-invoke during deserialization (if not, write a custom
    serializer).
    For other classes, the default assumption is that __init__ and __post_init__ might not correspond to the
    annotations and that their side effects are undesirable for deserialization, so we only call __new__
    and then manually `setattr` the fields. Write a custom serializer if this behavior doesn't work well
    for some class. For example, the following class will be serialized and deserialized correctly, but wouldn't
    if __init__ was called:

    ``` py
    class Example:
        i: int
        def __init__(self, i: int):
            self.i = i + 1
    ```

    The type hint (name of the class) given is ignored, instead we get the annotations from the class instance
    itself. This allows to deal with the frequent case of a type hint corresponding to a superclass of the class
    instance, e.g. an interface, which wouldn't provide the correct annotations and would require a custom
    serializer for the superclass (which would dispatch based on the actual type of the class instance given).

    The more precise class is used in the serialized form, allowing deserialization to know which precise class
    to handle as well.
    """

    targets = (_is_regular_class_instance,)

    def obj_to_pjson(self, cls_instance: Any, _type_hint: Any) -> Tuple[str, Dict[str, PJSONType]]:
        cls_fields_pjson: Dict[str, PJSONType] = {}
        fields_and_types = self._get_class_fields_and_types(
            cls_instance, as_dataclass=is_dataclass(cls_instance)
        )
        for field_name, field_type in fields_and_types.items():
            cls_fields_pjson[field_name] = self._service.to_pjson(
                getattr(cls_instance, field_name), field_type
            )
        cls_ref_pjson = self._service.to_pjson(cls_instance.__class__, Type)
        cls_ref_pjson = cast(str, cls_ref_pjson)
        return (cls_ref_pjson, cls_fields_pjson)

    def pjson_to_obj(self, pjson_obj: Tuple[str, Dict[str, PJSONType]], _type_hint: Any) -> Any:
        cls_ref_pjson, cls_fields_pjson = pjson_obj
        cls = self._service.from_pjson(cls_ref_pjson, Type)
        return self._deserialize_instance(cls, cls_fields_pjson)

    @staticmethod
    def _get_class_fields_and_types(cls: Any, as_dataclass: bool) -> Dict[str, Any]:
        """Return the field names and types for `cls`, a class or class instance."""
        if as_dataclass is True:
            # Fields for which init is False aren't serialized
            return {field.name: field.type for field in fields(cls) if field.init is True}
        else:
            # NOTE: in python >= 3.10, inspect.get_annotations() is a better choice
            return getattr(cls, "__annotations__", {})

    def _deserialize_instance(self, cls: Any, cls_fields_pjson: Dict[str, PJSONType]) -> Any:
        expected_fields_and_types = self._get_class_fields_and_types(
            cls, as_dataclass=is_dataclass(cls)
        )
        deserialized_fields = {
            field_name: self._service.from_pjson(cls_fields_pjson[field_name], field_type)
            for field_name, field_type in expected_fields_and_types.items()
        }
        if is_dataclass(cls):
            return cls(**deserialized_fields)
        else:
            cls_instance = cls.__new__(cls)
            for field_name, field in deserialized_fields.items():
                setattr(cls_instance, field_name, field)
            return cls_instance
