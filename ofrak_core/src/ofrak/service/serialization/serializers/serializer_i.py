from typing import Tuple, Type, Any, Union, Callable, TYPE_CHECKING

from abc import ABCMeta, abstractmethod

from ofrak.service.serialization.pjson_types import PJSONType

if TYPE_CHECKING:
    from ofrak.service.serialization.pjson import PJSONSerializationService


class SerializerInterface(metaclass=ABCMeta):
    # This is set from the `SerializationService` class itself, see its __init__()
    _service: "PJSONSerializationService"

    @property
    @abstractmethod
    def targets(self) -> Tuple[Union[Type, Callable[[Type], bool]], ...]:
        """
        Mandatory attribute telling the dependency injector which types this serializer is responsible for.

        Targets can be types, or predicates of a type hint returning whether the serializer handles this type.
        """
        raise NotImplementedError()

    @abstractmethod
    def obj_to_pjson(self, obj: Any, type_hint: Any) -> PJSONType:
        """Serialize the object to PJSON. Note that the generic `self._service.to_pjson` can be used here."""
        raise NotImplementedError()

    @abstractmethod
    def pjson_to_obj(self, pjson_obj: Any, type_hint: Any) -> Any:
        """Deserialize PJSON into the object. Note that the generic `self._service.from_pjson` can be used here."""
        raise NotImplementedError()
