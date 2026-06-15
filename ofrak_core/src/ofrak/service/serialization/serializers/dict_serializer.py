from typing import Any, Dict, Tuple, List, Union

from typing_inspect import get_origin, get_args

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class DictSerializer(SerializerInterface):
    """
    Serialize and deserialize `Dict[X, Y]` into `PJSONType`.

    Implementation: a list of tuples (key, value), because the serialized keys may not be hashable
    (e.g. if they're themselves serialized as a dictionary), despite the real keys being hashable.
    """

    targets = (lambda type_hint: get_origin(type_hint) == dict,)

    # Tuples are kept as tuples in PJSON, but serialized into lists in JSON.
    SerializedDictType = Union[List[Tuple[PJSONType, PJSONType]], List[List[PJSONType]]]

    def obj_to_pjson(self, obj: Dict[Any, Any], type_hint: Any) -> SerializedDictType:
        key_type, value_type = get_args(type_hint)
        return [
            (self._service.to_pjson(key, key_type), self._service.to_pjson(value, value_type))
            for key, value in obj.items()
        ]

    def pjson_to_obj(self, pjson_obj: SerializedDictType, type_hint: Any) -> Dict[Any, Any]:
        key_type, value_type = get_args(type_hint)
        return {
            self._service.from_pjson(key, key_type): self._service.from_pjson(value, value_type)
            for key, value in pjson_obj
        }
