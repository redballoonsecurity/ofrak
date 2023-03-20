from collections import OrderedDict
from dataclasses import dataclass
from enum import IntEnum
import re
from typing import Dict, List, Optional, Tuple
from ofrak.model.resource_model import ResourceIndexedAttribute
from ofrak.core.filesystem import FilesystemEntry
from ofrak.model.resource_model import Data
from ofrak.service.resource_service_i import ResourceAttributeValueFilter, ResourceFilter

from ofrak.resource import Resource


class SelectableAttributesError(Exception):
    """
    Prompt the user for an attribute to select with
    """


class ActionType(IntEnum):
    UNPACK = 0
    MOD = 1
    PACK = 2
    UNDEF = 3


@dataclass
class ScriptAction:
    action_type: ActionType
    action: str


class ScriptSession:
    hashed_actions: OrderedDict[int, ScriptAction] = OrderedDict()
    variable_mapping: Dict[bytes, str] = {}
    actions_counter: int = 0
    boilerplate_header: str = r"""
    from ofrak import OFRAK, OFRAKContext

    async def main(ofrak_context: OFRAKContext):
    """
    boilerplate_footer: str = r"""
    if __name__ == "__main__":
        ofrak = OFRAK()
        ofrak.run(main)
    """


class ScriptBuilder:
    """ """

    def __init__(self):
        self.root_cache: Dict[bytes, Resource] = {}
        self.script_sessions: Dict[bytes, ScriptSession] = {}
        self.selectable_indexes: List[ResourceIndexedAttribute] = [
            FilesystemEntry.Name,
            Data.Offset,
        ]

    async def _get_selector(self, resource: Resource) -> str:
        root_resource = await self._get_root_resource(resource)
        for ancestor in await resource.get_ancestors():
            if ancestor.get_id() in self.script_sessions[root_resource.get_id()].variable_mapping:
                break
        attribute, attribute_value = await self._get_selectable_attribute(resource)
        result = await ancestor.get_children(
            r_filter=ResourceFilter(
                tags=resource.get_most_specific_tags(),
                attribute_filters=[
                    ResourceAttributeValueFilter(attribute=attribute, value=attribute_value)
                ],
            )
        )
        if len(list(result)) != 1:
            raise SelectableAttributesError(
                f"Resource with ID {resource.get_id()} does not have a selectable attribute."
            )
        if isinstance(attribute_value, str) or isinstance(attribute_value, bytes):
            attribute_value = f'"{attribute_value}"'
        return f"""await {self.script_sessions[root_resource.get_id()].variable_mapping[ancestor.get_id()]}.get_children(
            r_filter=ResourceFilter(
                tags={resource.get_most_specific_tags()},
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        attribute={attribute.__name__}, 
                        value={attribute_value}
                    )
                ]   
            )
        )
        """

    async def _get_selectable_attribute(
        self, resource: Resource
    ) -> Tuple[ResourceIndexedAttribute, any]:
        for attribute in self.selectable_indexes:
            try:
                await resource.analyze(attribute.attributes_owner)
                attribute_value = attribute.get_value(resource.get_model())
            except Exception as e:
                print(e)
                continue
            return attribute, attribute_value
        raise SelectableAttributesError(
            f"Resource with ID {resource.get_id()} does not have a selectable attribute."
        )

    async def _generate_name(self, resource: Resource) -> str:
        root_resource = await self._get_root_resource(resource)
        # Find the most specific tag and use that with a number
        most_specific_tag = list(resource.get_most_specific_tags())[0].__name__.lower()
        _, selectable_attribute_value = await self._get_selectable_attribute(resource)
        name = f"{most_specific_tag}_{selectable_attribute_value}"
        name = re.sub(r"[-./\]", "_", name)
        if name in self.script_sessions[root_resource.get_id()].variable_mapping.values:
            parent = await resource.get_parent()
            return f"{self.script_sessions[root_resource.get_id()].variable_mapping[parent.get_id()]}_{name}"
        return name

    async def add_variable(self, resource: Resource) -> bytes:
        if await self._var_exists(resource):
            return await self._get_variable_from_session(resource)

        if resource == await self._get_root_resource(resource):
            await self._add_variable_to_session(resource, "root_resource")
            await self.add_action(
                resource,
                r"""root_resource = await context.create_root_resource_from_file()""",
                ActionType.UNDEF,
            )
            return "root_resource"
        parent = await resource.get_parent()
        if self._var_exists(parent.get_id()):
            await self.add_variable(parent)

        selector = await self._get_selector(resource)
        name = await self._generate_name(resource)
        await self.add_action(fr"""{name} = {selector}""")
        await self._add_variable_to_session(resource, name)
        return name

    async def add_action(
        self,
        resource: Resource,
        action: str,
        action_type: ActionType,
    ) -> None:
        """
        :param action:
        :param action_type:
        """
        root_resource = await self._get_root_resource(resource)
        session = self._get_session(root_resource.get_id())
        var_name = await self.add_variable(resource)
        qualified_action = action.replace("$resource", var_name)

        # TODO: actions are duplicated if page is refreshed, is this reasonable?
        session.hashed_actions[session.actions_counter] = ScriptAction(
            action_type, qualified_action
        )
        session.actions_counter += 1

    async def _add_variable_to_session(self, resource: Resource, var_name: str):
        root_resource = await self._get_root_resource(resource)
        self.script_sessions[root_resource.get_id()].variable_mapping[resource.get_id()] = var_name

    async def _get_variable_from_session(self, resource: Resource):
        root_resource = await self._get_root_resource(resource)
        return self.script_sessions[root_resource.get_id()].variable_mapping[resource.get_id()]

    async def _var_exists(self, resource: Resource):
        root_resource = await self._get_root_resource(resource)
        return resource.get_id() in self.script_sessions[root_resource.get_id()].variable_mapping

    def delete_action(self, resource_id: bytes, action: str) -> None:
        """
        :param action:
        """
        # TODO: do we really need to delete an action from the script?
        for key, script_action in self.script_sessions[resource_id].hashed_actions.items():
            if script_action.action == action:
                del self.script_sessions[resource_id].hashed_actions[key]

    def _get_session(self, resource_id: bytes) -> ScriptSession:
        session = self.script_sessions.get(resource_id, None)
        if session is None:
            session = ScriptSession()
            self.script_sessions[resource_id] = session

        return session

    async def get_script(self, resource: Resource) -> str:
        """
        :return script:
        """
        root_resource = await self._get_root_resource(resource)
        return self._get_script(root_resource.get_id())

    def _get_script(self, resource_id: bytes, target_type: Optional[ActionType] = None) -> str:
        script = []
        script.append(self.script_sessions[resource_id].boilerplate_header)
        for script_action in self.script_sessions[resource_id].hashed_actions.values():
            if target_type is None or target_type == script_action.action_type:
                script.append(f"\t{script_action.action}")
        script.append(self.script_sessions[resource_id].boilerplate_footer)
        "\n".join(script)

        return script

    def get_all_of_type(self, resource_id: bytes, target_type: ActionType) -> str:
        """
        :param target_type:
        :return script:
        """
        return self._get_script(resource_id, target_type)

    async def _get_root_resource(self, resource: Resource) -> Resource:
        if resource.get_id() in self.root_cache:
            return self.root_cache[resource.get_id()]
        while len(list(await resource.get_ancestors())) != 0:
            resource = await resource.get_parent()
        self.root_cache[resource.get_id()] = resource
        return resource

    def update_script(self, resource_id: bytes, action: str, action_type: ActionType) -> str:
        """
        :param action:
        :param action_type:
        :return script:
        """
        self.add_action(resource_id, action, action_type)
        return self.get_script(resource_id)
