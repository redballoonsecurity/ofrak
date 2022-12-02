from typing import Dict, Any

from sortedcontainers import SortedList

from ofrak.model.data_model import DataModel
from ofrak.service.data_service import DataService, _DataRoot, _Waypoint, DataId
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class DataRootSerializer(SerializerInterface):

    targets = (_DataRoot,)

    data_root_annotations = {
        "model": DataModel,
        "data": bytes,
        "_waypoints": Dict[int, _Waypoint],
        "_children": Dict[DataId, DataModel],
    }

    def obj_to_pjson(self, obj: _DataRoot, type_hint: Any) -> Dict[str, PJSONType]:
        data_root_pjson = {
            attr_name: self._service.to_pjson(getattr(obj, attr_name), type_hint)
            for attr_name, type_hint in self.data_root_annotations.items()
        }
        return data_root_pjson

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], type_hint: Any) -> _DataRoot:
        model = self._service.from_pjson(pjson_obj["model"], DataModel)
        data = self._service.from_pjson(pjson_obj["data"], bytes)
        waypoints = self._service.from_pjson(pjson_obj["_waypoints"], Dict[int, _Waypoint])
        children = self._service.from_pjson(pjson_obj["_children"], Dict[DataId, DataModel])
        data_root = _DataRoot(model, data)
        data_root._waypoints = waypoints
        data_root._waypoint_offsets = SortedList(waypoints.keys())
        data_root._children = children
        return data_root


class DataServiceSerializer(SerializerInterface):
    """
    Serialize and deserialize `DataService` into `PJSONType`.

    The `DataService` has some internal data structures which require custom
    serialization/deserialization, specifically the _DataRoot and _Waypoint. This is done with
    methods of this class, and avoids serializing redundant information.
    """

    targets = (DataService,)

    def obj_to_pjson(self, obj: DataService, _type_hint: Any) -> PJSONType:
        return self._service.to_pjson(getattr(obj, "_roots"), Dict[DataId, _DataRoot])

    def pjson_to_obj(self, pjson_obj: Dict[str, Dict], _type_hint: Any) -> DataService:
        model_store = {}
        roots = self._service.from_pjson(pjson_obj, Dict[DataId, _DataRoot])
        # The DataService assumes that the DataModel instance in the model store is the same
        # instance in the _DataRoot.model (and _DataRoot._children). Ensure that this is the case
        # before returning the DataService.
        for data_id, root_model in roots.items():
            model_store[data_id] = root_model.model
            for child in root_model.get_children():
                model_store[child.id] = child
        data_service: DataService = DataService.__new__(DataService)
        data_service._model_store = model_store
        data_service._roots = roots
        return data_service
