from collections.abc import Sequence, Iterable
from typing import Any, List, Union

from beartype import beartype
from typing_inspect import get_origin, get_args

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class SequenceSerializer(SerializerInterface):
    """
    Serialize and deserialize `List[X]`, `Sequence[X]` and `Iterable[X]` into `PJSONType`.

    Implementation: all of these are serialized as lists.
    """

    targets = (lambda type_hint: get_origin(type_hint) in (list, Sequence, Iterable),)

    SupportedSequenceType = Union[List[Any], Iterable, Sequence]

    @beartype
    def obj_to_pjson(self, obj: SupportedSequenceType, type_hint: Any) -> List[PJSONType]:
        args = get_args(type_hint)
        return [self._service.to_pjson(item, args[0]) for item in obj]

    @beartype
    def pjson_to_obj(self, pjson_obj: List[PJSONType], type_hint: Any) -> SupportedSequenceType:
        args = get_args(type_hint)
        return [self._service.from_pjson(item, args[0]) for item in pjson_obj]
