from typing import Any, List, Set

from typing_inspect import get_origin, get_args

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class SetSerializer(SerializerInterface):
    """
    Serialize and deserialize `Set[X]` into `PJSONType`.

    Implementation: sets are serialized as lists.
    """

    targets = (lambda type_hint: get_origin(type_hint) == set,)

    def obj_to_pjson(self, obj: Set[Any], type_hint: Any) -> List[PJSONType]:
        args = get_args(type_hint)
        return [self._service.to_pjson(item, args[0]) for item in obj]

    def pjson_to_obj(self, pjson_obj: List[PJSONType], type_hint: Any) -> Set[Any]:
        args = get_args(type_hint)
        return {self._service.from_pjson(item, args[0]) for item in pjson_obj}
