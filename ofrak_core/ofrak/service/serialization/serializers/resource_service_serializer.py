from collections import defaultdict
from typing import Any, List, Set, Tuple, cast, Callable
from typing import Dict, Optional

from sortedcontainers import SortedList
from typing_inspect import get_origin

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
    }

    def obj_to_pjson(self, obj: ResourceService, _type_hint: Any) -> Dict[str, PJSONType]:
        resource_service_pjson = {
            attr_name: self._service.to_pjson(getattr(obj, attr_name), type_hint)
            for attr_name, type_hint in self.resource_service_annotations.items()
        }
        resource_service_pjson["_tag_indexes"] = self._tag_index_to_pjson(obj._tag_indexes)
        resource_service_pjson["_root_resources"] = self._root_resources_to_pjson(
            obj._root_resources
        )
        return resource_service_pjson

    def pjson_to_obj(self, pjson_obj: Dict[str, PJSONType], _type_hint: Any) -> ResourceService:
        deserialized_attrs = {
            attr_name: self._service.from_pjson(pjson_obj[attr_name], type_hint)
            for attr_name, type_hint in self.resource_service_annotations.items()
        }
        deserialized_attrs["_tag_indexes"] = self._tag_index_from_pjson(pjson_obj["_tag_indexes"])
        deserialized_attrs["_root_resources"] = self._root_resources_from_pjson(
            pjson_obj["_root_resources"]
        )

        resource_service: ResourceService = ResourceService.__new__(ResourceService)
        for attr_name, attr in deserialized_attrs.items():
            if attr_name not in ("_attribute_indexes", "_tag_indexes"):
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

        # convert ID shorthand in _root_resources to actual nodes
        setattr(
            resource_service,
            "_root_resources",
            {
                root_id: resource_service._resource_store[root_id]
                for root_id in deserialized_attrs["_root_resources"]
            },
        )

        # convert ID shorthand in attribute indexes to actual nodes
        for attribute_index in deserialized_attrs["_attribute_indexes"].values():
            attribute_index.index = SortedList(
                [
                    (val, resource_service._resource_store[node_id])
                    for val, node_id in attribute_index.index
                ]
            )
        # _attribute_indexes is actually an AttributeIndexDict(ResourceAttributeIndex)
        setattr(
            resource_service,
            "_attribute_indexes",
            AttributeIndexDict(
                cast(Callable, ResourceAttributeIndex), deserialized_attrs["_attribute_indexes"]
            ),
        )

        # convert ID shorthand in tag indexes to actual nodes
        finished_tag_indexes = {
            tag: {resource_service._resource_store[node_id] for node_id in node_ids}
            for tag, node_ids in deserialized_attrs["_tag_indexes"].items()
        }
        # _tag_indexes is actually a defaultdict(set)
        setattr(resource_service, "_tag_indexes", defaultdict(set, finished_tag_indexes))

        return resource_service

    def _tag_index_to_pjson(self, tag_index: Dict[ResourceTag, Set[ResourceNode]]):
        simplified_index = {
            tag: {node.model.id for node in nodes} for tag, nodes in tag_index.items()
        }
        return self._service.to_pjson(simplified_index, Dict[ResourceTag, Set[bytes]])

    def _tag_index_from_pjson(self, tag_index_pjson: PJSONType):
        return self._service.from_pjson(tag_index_pjson, Dict[ResourceTag, Set[bytes]])

    def _root_resources_to_pjson(self, root_resources: Dict[bytes, ResourceNode]):
        return self._service.to_pjson(root_resources.keys(), Set[bytes])

    def _root_resources_from_pjson(self, root_resources_pjson: PJSONType) -> Set[bytes]:
        return self._service.from_pjson(root_resources_pjson, Set[bytes])


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


def _is_generic_resource_attribute_index(type_hint):
    return get_origin(type_hint) == ResourceAttributeIndex


class ResourceAttributeIndexSerializer(SerializerInterface):
    """
    Serialize and deserialize `ResourceAttributeIndex[T]` into `PJSONType`.

    The default serializer works for `ResourceAttributeIndex`, we just need to handle `ResourceAttributeIndex[T]`.
    This is done by ignoring the type argument and using `ResourceAttributeIndex` as type hint instead.
    """

    targets = (_is_generic_resource_attribute_index, ResourceAttributeIndex)

    def obj_to_pjson(self, obj: ResourceAttributeIndex, type_hint: Any) -> PJSONType:
        simplified_index = [(val, node.model.id) for val, node in obj.index]
        result = {
            "_attribute": self._service.to_pjson(obj._attribute, ResourceIndexedAttribute),
            "index": self._service.to_pjson(simplified_index, List[Tuple[Any, bytes]]),
            "values_by_node_id": self._service.to_pjson(obj.values_by_node_id, Dict[bytes, Any]),
        }
        return result

    def pjson_to_obj(self, pjson_obj: PJSONType, type_hint: Any) -> ResourceAttributeIndex:
        if not isinstance(pjson_obj, dict):
            raise ValueError(f"Expected to deserialize a dict, got {type(pjson_obj)}")
        deserialized_attrs = {
            "_attribute": self._service.from_pjson(
                pjson_obj["_attribute"], ResourceIndexedAttribute
            ),
            "index": self._service.from_pjson(pjson_obj["index"], List[Tuple[Any, bytes]]),
            "values_by_node_id": self._service.from_pjson(
                pjson_obj["values_by_node_id"], Dict[bytes, Any]
            ),
        }

        reconstructed_index = ResourceAttributeIndex(deserialized_attrs["_attribute"])
        reconstructed_index.index = SortedList(deserialized_attrs["index"])
        reconstructed_index.values_by_node_id = deserialized_attrs["values_by_node_id"]

        return reconstructed_index  # Only partially reconstructed
