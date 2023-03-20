from collections import OrderedDict
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional

from ofrak_type.error import NotFoundError
from ofrak.resource import Resource


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
        self.script_sessions: Dict[bytes, ScriptSession] = {}

    async def add_action(self, resource: Resource, action: str, action_type: ActionType) -> None:
        """
        :param action:
        :param action_type:
        """
        root_resource = await self._get_root_resource(resource)
        session = self._get_session(root_resource.get_id())

        # TODO: actions are duplicated if page is refreshed, is this reasonable?
        session.hashed_actions[session.actions_counter] = ScriptAction(action_type, action)
        session.actions_counter += 1

    def add_variable(self, root_resource_id: bytes, resource: Resource, var_name: str):
        # TODO: autogenerate variable name here instead of passing it in
        self.script_sessions[root_resource_id].variable_mapping[resource.get_id()] = var_name

    def delete_action(self, resource_id: bytes, action: str) -> None:
        """
        :param action:
        """
        # TODO: do we really need to delete an action from the script?
        for key, script_action in self.script_sessions[resource_id].hashed_actions.items():
            if script_action.action == action:
                del self.script_sessions[resource_id].hashed_actions[key]

    async def _generate_name(self, resource) -> str:
        pass

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
        parent = resource
        try:
            # Assume get_ancestors returns an ordered list with the parent first and the root last
            for parent in await resource.get_ancestors():
                pass
        except NotFoundError:
            pass

        return parent

    async def _get_var_name(self, resource: Resource) -> str:
        root_resource = await self._get_root_resource(resource)
        root_resource_id = root_resource.get_id()
        resource_id = resource.get_id()
        if resource_id in self.script_sessions[root_resource_id].variable_mapping.keys():
            return self.script_sessions[root_resource_id].variable_mapping[resource_id]
        selector = self.get_selector(resource)
        name = self.generate_name(resource)
        self.script_sessions[root_resource_id].variable_mapping[resource_id] = name
        self.add_action(resource, f"{name} = {selector}", ActionType.MOD)
        return name

    def update_script(self, resource_id: bytes, action: str, action_type: ActionType) -> str:
        """
        :param action:
        :param action_type:
        :return script:
        """
        self.add_action(resource_id, action, action_type)
        return self.get_script(resource_id)
