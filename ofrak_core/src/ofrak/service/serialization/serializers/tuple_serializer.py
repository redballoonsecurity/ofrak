from typing import Any, Tuple, Union, List, Callable

from beartype import beartype
from typing_inspect import get_origin, get_args

from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class TupleSerializer(SerializerInterface):
    """
    Serialize and deserialize `Tuple[...]` into `PJSONType`.
    """

    targets = (lambda type_hint: get_origin(type_hint) == tuple,)

    @beartype
    def obj_to_pjson(self, obj: Tuple, type_hint: Any) -> Tuple:
        return self._handle(obj, type_hint, self._service.to_pjson)

    @beartype
    def pjson_to_obj(self, pjson_obj: Union[List, Tuple], type_hint: Any) -> Tuple:
        return self._handle(pjson_obj, type_hint, self._service.from_pjson)

    def _handle(self, obj: Union[List, Tuple], type_hint: Any, factory: Callable) -> Tuple:
        args = get_args(type_hint)
        if Ellipsis in args:
            # Tuple[X, ...]. All items are expected to be of type `X`.
            return tuple(factory(item, args[0]) for item in obj)
        else:
            # e.g. Tuple[X, Y, Z]
            if len(args) != len(obj):
                raise TypeError(f"invalid tuple size for {obj} with expected type {type_hint}")
            return tuple(factory(item, arg) for item, arg in zip(obj, args))
