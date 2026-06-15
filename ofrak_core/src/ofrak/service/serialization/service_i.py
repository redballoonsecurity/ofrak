from typing import Any

from abc import ABC, abstractmethod

from ofrak.service.serialization.pjson_types import PJSONType


class SerializationServiceInterface(ABC):
    """
    Interface for a serialization service.

    Note that the interface is currently tightly coupled with the PJSON implementation. This is because other parts
    of the code expect and process the PJSON format, so the serialization format can't be trivially replaced with
    another one at the moment.
    """

    @abstractmethod
    def to_pjson(self, obj: Any, type_hint: Any) -> PJSONType:
        raise NotImplementedError()

    @abstractmethod
    def from_pjson(self, pjson_obj: PJSONType, type_hint: Any) -> Any:
        raise NotImplementedError()

    @abstractmethod
    def to_json(self, obj: Any, type_hint: Any) -> str:
        raise NotImplementedError()

    @abstractmethod
    def from_json(self, json_obj: str, type_hint: Any) -> Any:
        raise NotImplementedError()
