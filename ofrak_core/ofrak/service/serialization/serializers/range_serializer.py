from typing import Any, Tuple

from ofrak.service.serialization.serializers.serializer_i import SerializerInterface
from ofrak_type.range import Range


class RangeSerializer(SerializerInterface):
    """
    Serialize and deserialize `Range` into `PJSONType`.

    Implementation: a `Range` is serialized as a 2-tuple (start, end).

    The default class instance serializer would work, however the space overhead would be
    significant and `Range` is used frequently enough in OFRAK to justify this optimization.
    """

    targets = (Range,)

    def obj_to_pjson(self, obj: Range, _type_hint: Any) -> Tuple[int, int]:
        return (obj.start, obj.end)

    def pjson_to_obj(self, pjson_obj: Tuple[int, int], _type_hint: Any) -> Range:
        return Range(pjson_obj[0], pjson_obj[1])
