from typing import Any, Tuple

import os

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class OsStatResultSerializer(SerializerInterface):
    """
    Serialize and deserialize `os.stat_result` into `PJSONType`.

    `os.stat_result` is basically a wrapper around a tuple of ints, so we can serialize it as that tuple.
    """

    targets = (os.stat_result,)

    def obj_to_pjson(self, obj: os.stat_result, type_hint: Any) -> PJSONType:
        return self._service.to_pjson(obj, Tuple[int, ...])

    def pjson_to_obj(self, pjson_obj: PJSONType, type_hint: Any) -> os.stat_result:
        return os.stat_result(pjson_obj)  # type: ignore
