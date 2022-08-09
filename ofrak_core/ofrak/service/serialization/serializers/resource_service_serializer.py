from collections import defaultdict
from typing import Any, List, Set
from typing import Dict, Optional

from ofrak import ResourceTag
from ofrak.model.resource_model import ResourceIndexedAttribute
from ofrak.service.resource_service import (
    ResourceNode,
    ResourceAttributeIndex,
    AttributeIndexDict,
    T,
)
from ofrak.service.resource_service import ResourceService
from ofrak.service.serialization.pjson_types import PJSONType
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface


class ResourceServiceSerializer(SerializerInterface):
    """
    Serialize and deserialize `ResourceService` into `PJSONType`.

    The challenging thing to serialize and deserialize is the `ResourceNode` store. This class
    complements the `ResourceNodeSerializer`, which doesn't fully serialize the parents and children of a
    node. So during deserialization, the major role of this class is to finalize the deserialization
    of the `ResourceNode` objects, by recovering their parents and children and updating the `ResourceNode`s.

    Also, _attribute_indexes is actually an AttributeIndexDict(ResourceAttributeIndex) (a kind of defaultdict),
    and _tag_indexes is a defaultdict(set). They're both serialized as dicts, but deserialized as the correct
    defaultdicts.
    """

    targets = (ResourceService,)

    resource_service_annotations = {
        "_resource_store": Dict[bytes, ResourceNode],
        "_resource_by_data_id_store": Dict[bytes, ResourceNode],
        "_attribute_indexes": Dict[ResourceIndexedAttribute[T], ResourceAttributeIndex[T]],
        "_tag_indexes": Dict[ResourceTag, Set[ResourceNode]],
        "_root_resources": Dict[bytes, ResourceNode],
    }

    def obj_to_pjson(self, obj: ResourceService, _type_hint: Any) -> Dict[str, PJSONType]:
        return {
            attr_name: self._service.to_pjson(getattr(obj, attr_name), type_hint)
            for attr_name, type_hint in self.resource_service_annotations.items()
        }

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], _type_hint: Any) -> ResourceService:
        deserialized_attrs = {
            attr_name: self._service.from_pjson(pjson_obj[attr_name], type_hint)
            for attr_name, type_hint in self.resource_service_annotations.items()
        }
        # _attribute_indexes is actually an AttributeIndexDict(ResourceAttributeIndex)
        deserialized_attrs["_attribute_indexes"] = AttributeIndexDict(
            ResourceAttributeIndex, deserialized_attrs["_attribute_indexes"]  # type: ignore
        )
        # _tag_indexes is actually a defaultdict(set)
        deserialized_attrs["_tag_indexes"] = defaultdict(set, deserialized_attrs["_tag_indexes"])

        resource_service: ResourceService = ResourceService.__new__(ResourceService)
        for attr_name, attr in deserialized_attrs.items():
            setattr(resource_service, attr_name, attr)

        for resource_node in resource_service._resource_store.values():
            # Update `parent`
            parent_id: Optional[bytes] = resource_node.model.parent_id
            if parent_id is None:
                parent = None
            else:
                parent = resource_service._resource_store[parent_id]
            resource_node.parent = parent
            # Update `_children`
            resource_node._children = [
                resource_service._resource_store[child_id]
                for child_id in getattr(resource_node, "_pjson_children_ids")
            ]
            delattr(resource_node, "_pjson_children_ids")

        return resource_service


class ResourceNodeSerializer(SerializerInterface):
    """
    Serialize and deserialize `ResourceNode` into `PJSONType`.

    This requires a custom serializer because of the infinite recursion the default serializer
    would encounter, with a ResourceNode storing instances of both its parent and children.

    Implementation:
    - the parent isn't serialized;
    - children are serialized as the IDs of their ResourceModel instead of the children themselves.

    The deserialized `ResourceNode` will be temporary and will need to be updated by the `ResourceService` deserializer.
    Its fields `parent` and `_children` aren't set, instead:
     - the parent can be retrieved from the `parent_id` of the ResourceModel;
    - children can be found from their IDs stored in a temporary field `_pjson_children_ids`.
    Recovering these attributes is the role of the `ResourceServiceSerializer`.
    """

    targets = (ResourceNode,)

    serialized_annotations = {
        attr_name: attr_type
        for attr_name, attr_type in ResourceNode.__annotations__.items()
        if attr_name not in ("parent", "_children")
    }

    def obj_to_pjson(self, obj: ResourceNode, _type_hint: Any) -> Dict[str, PJSONType]:
        result = {}
        for attr_name, type_hint in self.serialized_annotations.items():
            result[attr_name] = self._service.to_pjson(getattr(obj, attr_name), type_hint)
        children_ids = [child.model.id for child in obj._children]
        result["_pjson_children_ids"] = self._service.to_pjson(children_ids, List[bytes])
        return result

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], _type_hint: Any) -> ResourceNode:
        deserialized_attrs = {
            attr_name: self._service.from_pjson(pjson_obj[attr_name], type_hint)
            for attr_name, type_hint in self.serialized_annotations.items()
        }
        deserialized_attrs.update({"parent": None, "_children": []})
        resource_node = ResourceNode.__new__(ResourceNode)
        for attr_name, attr in deserialized_attrs.items():
            setattr(resource_node, attr_name, attr)
        setattr(
            resource_node,
            "_pjson_children_ids",
            self._service.from_pjson(pjson_obj["_pjson_children_ids"], List[bytes]),
        )
        return resource_node
