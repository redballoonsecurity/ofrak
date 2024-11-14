from typing import Any, Tuple, List, Union

from ofrak.core.patch_maker.modifiers import SourceBundle
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class SourceBundleSerializer(SerializerInterface):
    """
    Serialize and deserialize `Dict[X, Y]` into `PJSONType`.

    Implementation: a list of tuples (key, value), because the serialized keys may not be hashable
    (e.g. if they're themselves serialized as a dictionary), despite the real keys being hashable.
    """

    targets = (SourceBundle,)

    # Tuples are kept as tuples in PJSON, but serialized into lists in JSON.
    SerializedDictType = Union[List[Tuple[PJSONType, PJSONType]], List[List[PJSONType]]]

    def obj_to_pjson(self, obj: SourceBundle, type_hint: Any) -> SerializedDictType:
        return [
            (self._service.to_pjson(key, str), self._serialize_value(value))
            for key, value in obj.items()
        ]

    def pjson_to_obj(self, pjson_obj: SerializedDictType, type_hint: Any) -> SourceBundle:
        return SourceBundle(
            [
                (self._service.from_pjson(key, str), self._deserialize_value(value))
                for key, value in pjson_obj
            ]
        )

    def _serialize_value(self, value: Union[bytes, SourceBundle]) -> PJSONType:
        if isinstance(value, SourceBundle):
            return self.obj_to_pjson(value, SourceBundle)
        else:
            # TODO: Only serializing as strings for the GUI SourceBundle inputs, which are
            #  strings, instead of bytes as they should be
            string_value: str = value.decode("utf-8")
            return self._service.to_pjson(string_value, str)

    def _deserialize_value(self, value: Any) -> Union[bytes, SourceBundle]:
        if isinstance(value, str):
            # TODO: Only deserializing from strings for the GUI SourceBundle inputs, which are
            #  strings, instead of bytes as they should be
            deserialized_string: str = self._service.from_pjson(value, str)
            return deserialized_string.encode("utf-8")
        else:
            return self._service.from_pjson(value, SourceBundle)
