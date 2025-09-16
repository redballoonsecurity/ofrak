from typing import Any, List, Dict

import orjson
from inspect import isfunction

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface
from ofrak.service.serialization.service_i import SerializationServiceInterface


class PJSONSerializationService(SerializationServiceInterface):
    """
    Service handling the serialization and deserialization of various types into a JSON-compatible Python type
    named PJSON (for "proto-JSON"). The idea is that this is a Python type, making its handling easier, but which has a
    straightforward mapping to real JSON via json.dump() or json.load().

    In this model, JSON serialization happens in two stages: object to PJSON, then PJSON to JSON (string).
    Deserialization works the same way: JSON (string) to PJSON, then PJSON to object.

    Note that the PJSON representation of an object might be the object itself, for example to_pjson(1, int) == 1.
    """

    def __init__(self, serializers: List[SerializerInterface]):
        """
        This class should be instantiated via the dependency injector. This assumes that the `serializers`
        module has been discovered.
        """
        self._serializers = serializers
        for serializer in self._serializers:
            # This class requires the custom serializers, and the custom serializers require this class.
            # Hacky workaround for this circular dependency.
            setattr(serializer, "_service", self)

        # Used to cache results of serializer discovery
        self._cached_type_to_serializer_mapping: Dict[Any, SerializerInterface] = {}

    def to_pjson(self, obj: Any, type_hint: Any) -> PJSONType:
        """
        Generic function to recursively convert `obj` into PJSON.

        The following type hints are supported:

        - Tuple, List, Sequence, Iterable
        - Dict
        - Set
        - Union, and its special case Optional
        (NOTE: Union should only be used with mutually exclusive types, and types with different PJSON representations.
        For example, serializing bytes as Union[str, bytes] will work, but then since both str and bytes are serialized as
        str, deserialization won't be able to figure out whether the PJSON str object should be decoded as str or bytes.
        In practice, all types within the Union are tried in order, and the first that works is selected. So serializing
        then deserializing bytes as Union[str, bytes] will result in a str, not the original bytes. This should be
        considered an implementation detail, though: relying on the order of the types within the Union isn't encouraged.)
        - int, float, bool, str
        - type(None)
        - bytes
        - enum.Enum, or any type hint corresponding to a subclass of enum.Enum
        - Type[X], type or another metaclass, when `obj` is a class and should be serialized as a reference to itself
        - dataclass instances
        - other class instances. This will work if the class has type annotations which correspond to the arguments in its
        __init__() method, and the attributes don't change meaningfully as they go through __init__() (i.e. the class
        isn't too different from a dataclass).
        - Any, only if the object is already of PJSONType. Otherwise TypeError is raised. (prefer specific types whenever
        possible)

        If any type is found during recursion that isn't in this list, a TypeError exception is raised.
        """
        serializer = self._get_serializer(obj, type_hint)
        return serializer.obj_to_pjson(obj, type_hint)

    def from_pjson(self, pjson_obj: PJSONType, type_hint: Any) -> Any:
        """Opposite of `to_pjson`."""
        serializer = self._get_serializer(pjson_obj, type_hint)
        return serializer.pjson_to_obj(pjson_obj, type_hint)

    def _get_serializer(self, obj: Any, type_hint: Any) -> SerializerInterface:
        """Return the first serializer/deserializer pair found for `type_hint`."""
        # Has this type already been seen?
        try:
            return self._cached_type_to_serializer_mapping[type_hint]
        except KeyError:
            pass
        # First pass: `targets` as explicit types have priority over predicates
        for serializer in self._serializers:
            for target in serializer.targets:
                if not isfunction(target) and target == type_hint:
                    self._cached_type_to_serializer_mapping[type_hint] = serializer
                    return serializer
        # Second pass: if the type hint didn't correspond to any explicit type, try predicates
        for serializer in self._serializers:
            for target in serializer.targets:
                if isfunction(target) and target(type_hint) is True:
                    self._cached_type_to_serializer_mapping[type_hint] = serializer
                    return serializer
        raise TypeError(f"Unrecognized type hint {type_hint} for {obj}")

    def dumps(self, pjson_obj: PJSONType) -> str:
        """Wrapper around the dumping method of the JSON library used."""
        return orjson.dumps(pjson_obj).decode("utf-8")

    def loads(self, json_obj: str) -> PJSONType:
        """Wrapper around the loading method of the JSON library used."""
        return orjson.loads(bytes(json_obj, "utf-8"))

    def to_json(self, obj: Any, type_hint: Any) -> str:
        return self.dumps(self.to_pjson(obj, type_hint))

    def from_json(self, json_obj: str, type_hint: Any) -> Any:
        return self.from_pjson(self.loads(json_obj), type_hint)
