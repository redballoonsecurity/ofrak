from typing import Union, Any, Callable

from beartype import beartype
from beartype.roar import BeartypeCallHintParamViolation
from typeguard import check_type
from typing_inspect import get_origin, get_args

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class UnionSerializer(SerializerInterface):
    """
    Serialize and deserialize `Union[...]` into `PJSONType`.

    This includes Optional, as Optional[X] == Union[X, type(None)]

    Implementation: all types in the Union are tried in order, and the first for which
    handling doesn't return an error is used.
    """

    targets = (lambda type_hint: get_origin(type_hint) == Union,)

    def to_pjson_checking_type(self, obj: Any, type_hint: Any) -> PJSONType:
        check_type("obj", obj, type_hint)
        return self._service.to_pjson(obj, type_hint)

    def from_pjson_checking_type(self, pjson_obj: PJSONType, type_hint: Any) -> Any:
        obj = self._service.from_pjson(pjson_obj, type_hint)
        check_type("obj", obj, type_hint)
        return obj

    @beartype
    def obj_to_pjson(self, obj: Any, type_hint: Any) -> PJSONType:
        return self._try_all_types(obj, type_hint, self.to_pjson_checking_type)

    @beartype
    def pjson_to_obj(self, pjson_obj: PJSONType, type_hint: Any) -> Any:
        return self._try_all_types(pjson_obj, type_hint, self.from_pjson_checking_type)

    def _try_all_types(self, obj: Any, type_hint: Any, handler: Callable[[Any, Any], Any]) -> Any:
        args = get_args(type_hint)
        failure_reasons = dict()
        for arg in args:
            try:
                return handler(obj, arg)
            except (TypeError, BeartypeCallHintParamViolation, AttributeError, KeyError) as e:
                failure_reasons[arg] = e
        reasons_string = "\n".join(f"{arg}: {reason}" for arg, reason in failure_reasons.items())
        raise TypeError(
            f"Couldn't run {handler.__name__} on {obj} with any of the types:\n{reasons_string}"
        )
