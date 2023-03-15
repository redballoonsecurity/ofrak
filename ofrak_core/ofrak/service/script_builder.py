from collections import OrderedDict
from dataclasses import dataclass
from enum import IntEnum


class ActionType(IntEnum):
    UNPACK = 0
    MOD = 1
    PACK = 2
    UNDEF = 3


@dataclass
class ScriptAction:
    action_type: ActionType
    action: str


class ScriptBuilder:
    """ """

    def __init__(self):
        self.hashed_actions = OrderedDict()
        self.actions_counter = 0
        self.boilerplate_header = r"""
        from ofrak import OFRAK, OFRAKContext

        async def main(ofrak_context: OFRAKContext):
        """
        self.boilerplate_footer = r"""

        if __name__ == "__main__":
            ofrak = OFRAK()
            ofrak.run(main)
        """

    def add_action(self, action: str, action_type: ActionType) -> None:
        """
        :param action:
        :param action_type:
        """
        # TODO: is this the best data structure and key to use?
        # TODO: actions are duplicated if page is refreshed.
        # TODO: script persists across resources, not desired.
        self.hashed_actions[self.actions_counter] = ScriptAction(action_type, action)
        self.actions_counter += 1

    def delete_action(self, action: str) -> None:
        """
        :param action:
        """
        # TODO: do we really need to delete an action from the script?
        for key, script_action in self.hashed_actions.items():
            if script_action.action == action:
                del self.hashed_actions[key]

    def get_script(self) -> str:
        """
        :return script:
        """
        script = [self.boilerplate_header]
        for script_action in self.hashed_actions.values():
            script.append(f"\t{script_action.action}")
        script.append(self.boilerplate_footer)
        "\n".join(script)

        return script

    def get_all_of_type(self, target_type: ActionType) -> str:
        """
        :param target_type:
        :return script:
        """
        script = [self.boilerplate_header]
        for script_action in self.hashed_actions.values():
            if script_action.action_type == target_type:
                script.append(f"\t{script_action.action}")
        script.append(self.boilerplate_footer)
        "\n".join(script)

        return script

    def update_script(self, action: str, action_type: ActionType) -> str:
        """
        :param action:
        :param action_type:
        :return script:
        """
        self.add_action(action, action_type)
        return self.get_script()
