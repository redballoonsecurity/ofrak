from typing import Any

from angr import Project

from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class AngrAnalysisSerializer(SerializerInterface):
    """
    Dummy serializer to silently pass serialization attempts, and hard fail on attempting to
    deserialize.
    """

    targets = (Project,)

    def obj_to_pjson(self, obj: Project, type_hint: Any) -> PJSONType:
        return None

    def pjson_to_obj(self, pjson_obj: Any, type_hint: Any) -> Project:
        raise NotImplementedError("Deserialization for Angr projects is not yet supported!")
