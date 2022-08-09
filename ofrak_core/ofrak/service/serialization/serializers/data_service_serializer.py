from typing import Any, List, Tuple
from typing import Dict, Optional

from ofrak.service.data_service import DataNode
from ofrak.service.data_service import DataService
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class DataServiceSerializer(SerializerInterface):
    """
    Serialize and deserialize `DataService` into `PJSONType`.

    The challenging thing to serialize and deserialize is the `DataNode` store. This class
    complements the `DataNodeSerializer`, which doesn't fully serialize the parents and children of a
    node. So during deserialization, the major role of this class is to finalize the deserialization
    of the `DataNode` objects, by recovering their parents and children and updating the `DataNode`s.
    """

    targets = (DataService,)

    usable_annotations = DataService.__annotations__

    def obj_to_pjson(self, obj: DataService, _type_hint: Any) -> Dict[str, PJSONType]:
        return {
            attr_name: self._service.to_pjson(getattr(obj, attr_name), type_hint)
            for attr_name, type_hint in self.usable_annotations.items()
        }

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], _type_hint: Any) -> DataService:
        deserialized_attrs = {
            attr_name: self._service.from_pjson(pjson_obj[attr_name], type_hint)
            for attr_name, type_hint in self.usable_annotations.items()
        }
        data_service: DataService = DataService.__new__(DataService)
        for attr_name, attr in deserialized_attrs.items():
            setattr(data_service, attr_name, attr)

        for data_node in data_service._data_node_store.values():
            # Update `parent`
            parent_id: Optional[bytes] = data_node.model.parent_id
            if parent_id is None:
                parent = None
            else:
                parent = data_service._data_node_store[parent_id]
            data_node.parent = parent
            # Update `_children`
            children_ids = getattr(data_node, "_pjson_children_ids")
            data_node._children = []
            for child_position, child_id in children_ids:
                data_node._children.append(
                    (child_position, data_service._data_node_store[child_id])
                )
            delattr(data_node, "_pjson_children_ids")

        return data_service


class DataNodeSerializer(SerializerInterface):
    """
    Serialize and deserialize `DataNode` into `PJSONType`.

    This requires a custom serializer because of the infinite recursion the default serializer
    would encounter, with a DataNode storing instances of both its parent and children.

    Implementation:
    - the parent isn't serialized;
    - children are serialized as the IDs of their DataModel instead of the children themselves.

    The deserialized `DataNode` will be temporary and will need to be updated by the `DataService` deserializer.
    Its fields `parent` and `_children` aren't set, instead:
     - the parent can be retrieved from the `parent_id` of the DataModel;
    - children can be found from their IDs stored in a temporary field `_pjson_children_ids`.
    Recovering these attributes is the role of the `DataServiceSerializer`.
    """

    targets = (DataNode,)

    serialized_annotations = {
        attr_name: attr_type
        for attr_name, attr_type in DataNode.__annotations__.items()
        if attr_name not in ("parent", "_children")
    }

    def obj_to_pjson(self, obj: DataNode, _type_hint: Any) -> PJSONType:
        result = {}
        for attr_name, type_hint in self.serialized_annotations.items():
            result[attr_name] = self._service.to_pjson(getattr(obj, attr_name), type_hint)
        children_ids = [(child_position, child.model.id) for child_position, child in obj._children]
        result["_pjson_children_ids"] = self._service.to_pjson(
            children_ids, List[Tuple[int, bytes]]
        )
        return result

    def pjson_to_obj(self, pjson_obj: Any, _type_hint: Any) -> DataNode:
        deserialized_attrs = {
            attr_name: self._service.from_pjson(pjson_obj[attr_name], type_hint)
            for attr_name, type_hint in self.serialized_annotations.items()
        }
        deserialized_attrs.update({"parent": None, "_children": []})
        data_node = DataNode.__new__(DataNode)
        for attr_name, attr in deserialized_attrs.items():
            setattr(data_node, attr_name, attr)
        setattr(
            data_node,
            "_pjson_children_ids",
            self._service.from_pjson(pjson_obj["_pjson_children_ids"], List[Tuple[int, bytes]]),
        )
        return data_node
