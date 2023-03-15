from collections import OrderedDict


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
        \n
        if __name__ == "__main__":
            \tofrak = OFRAK()
            \tofrak.run(main)
        """

    def add_action(self, script_action: str):
        # TODO: is this the best data structure and key to use?
        # TODO: actions are duplicated if page is refreshed.
        # TODO: script persists across resources, not desired.
        self.hashed_actions[self.actions_counter] = script_action
        self.actions_counter += 1

    def delete_action(self, script_action: str):
        # TODO: do we really need to delete an action from the script?
        for key, value in self.hashed_actions.items():
            if value == script_action:
                del self.hashed_actions[key]

    def get_script(self):
        script = [self.boilerplate_header]
        for action in self.hashed_actions.values():
            script.append(f"\t{action}")
        script.append(self.boilerplate_footer)
        "\n".join(script)

        return script

    def update_script(self, script_action: str):
        self.add_action(script_action)
        return self.get_script()
