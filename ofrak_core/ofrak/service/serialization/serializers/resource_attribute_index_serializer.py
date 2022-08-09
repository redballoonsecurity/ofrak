from typing import Any

from typing_inspect import get_origin

from ofrak.service.resource_service import ResourceAttributeIndex
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


def _is_generic_resource_attribute_index(type_hint):
    return get_origin(type_hint) == ResourceAttributeIndex


class ResourceAttributeIndexSerializer(SerializerInterface):
    """
    Serialize and deserialize `ResourceAttributeIndex[T]` into `PJSONType`.

    The default serializer works for `ResourceAttributeIndex`, we just need to handle `ResourceAttributeIndex[T]`.
    This is done by ignoring the type argument and using `ResourceAttributeIndex` as type hint instead.
    """

    targets = (_is_generic_resource_attribute_index,)

    def obj_to_pjson(self, obj: ResourceAttributeIndex, type_hint: Any) -> PJSONType:
        return self._service.to_pjson(obj, ResourceAttributeIndex)

    def pjson_to_obj(self, pjson_obj: PJSONType, type_hint: Any) -> ResourceAttributeIndex:
        return self._service.from_pjson(pjson_obj, ResourceAttributeIndex)
