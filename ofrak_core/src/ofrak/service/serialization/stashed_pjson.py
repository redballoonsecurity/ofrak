from collections import defaultdict
from typing import Any, Dict, cast

from itertools import product

from ofrak.service.serialization.pjson import PJSONSerializationService
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.service_i import SerializationServiceInterface


def _short_string_generator():
    """Generator of short JSON-compatible strings of increasing size."""
    disallowed_characters = [0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74, 0x75]
    alphabet = [chr(i) for i in range(0x20, 0x7E) if i not in disallowed_characters]
    size = 1
    while True:
        for letters in product(*([alphabet] * size)):
            yield "".join(letters)
        size += 1


class StashedPJSONSerializationService(SerializationServiceInterface):
    """
    Serialization service producing a more compact encoding than `PJSONSerializationService`, at the expense of time
    performance, by mapping each string in the PJSON to a shorter one, and including the mapping at the beginning of
    the serialized form.
    """

    def __init__(self, serializer: PJSONSerializationService):
        self._serializer = serializer

    def to_pjson(self, obj: Any, type_hint: Any) -> PJSONType:
        pjson = self._serializer.to_pjson(obj, type_hint)
        return self._shorten(pjson)

    def from_pjson(self, pjson_obj: PJSONType, type_hint: Any) -> Any:
        restored_pjson = self._restore(pjson_obj)
        return self._serializer.from_pjson(restored_pjson, type_hint)

    def to_json(self, obj: Any, type_hint: Any) -> str:
        return self._serializer.dumps(self.to_pjson(obj, type_hint))

    def from_json(self, json_obj: str, type_hint: Any) -> Any:
        return self.from_pjson(self._serializer.loads(json_obj), type_hint)

    def _shorten(self, pjson: PJSONType) -> Dict[str, PJSONType]:
        strings_long_to_short: Dict[str, str] = defaultdict(_short_string_generator().__next__)
        shortened_pjson = self._convert(pjson, strings_long_to_short)
        return {
            "string_mapping": {short: long for long, short in strings_long_to_short.items()},
            "shortened_pjson": shortened_pjson,
        }

    def _restore(self, shortened_pjson: PJSONType) -> PJSONType:
        pjson_obj = cast(Dict[str, PJSONType], shortened_pjson)
        strings_short_to_long = pjson_obj["string_mapping"]
        strings_short_to_long = cast(Dict[str, str], strings_short_to_long)
        shortened_pjson = pjson_obj["shortened_pjson"]
        return self._convert(shortened_pjson, strings_short_to_long)

    def _convert(
        self,
        pjson: PJSONType,
        string_mapping: Dict[str, str],
    ) -> PJSONType:
        """
        Perform the string replacement according to `string_mapping`.

        This method is used for both encoding and decoding, with opposite `string_mapping` dictionaries.
        """
        if isinstance(pjson, str):
            return string_mapping[pjson]
        elif isinstance(pjson, list):
            return [self._convert(item, string_mapping) for item in pjson]
        elif isinstance(pjson, tuple):
            return tuple(self._convert(item, string_mapping) for item in pjson)
        elif isinstance(pjson, dict):
            return {
                cast(str, self._convert(key, string_mapping)): self._convert(value, string_mapping)
                for key, value in pjson.items()
            }
        else:
            return pjson
