from collections import OrderedDict
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional


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

    def add_action(self, resource_id: bytes, action: str, action_type: ActionType) -> None:
        """
        :param action:
        :param action_type:
        """
        session = self._get_session(resource_id)

        # TODO: actions are duplicated if page is refreshed, is this reasonable?
        session.hashed_actions[session.actions_counter] = ScriptAction(action_type, action)
        session.actions_counter += 1

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

    def get_script(self, resource_id: bytes) -> str:
        """
        :return script:
        """
        return self._get_script(resource_id)

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

    def update_script(self, resource_id: bytes, action: str, action_type: ActionType) -> str:
        """
        :param action:
        :param action_type:
        :return script:
        """
        self.add_action(resource_id, action, action_type)
        return self.get_script(resource_id)
