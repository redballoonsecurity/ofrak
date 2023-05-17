from dataclasses import dataclass

from typing import Tuple, Dict

from ofrak.resource import Resource

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig


@dataclass
class UserScript(ComponentConfig):
    code: str
    args: Tuple[str, ...]
    kwargs: Dict[str, str]


class RunScriptModifier(Modifier[UserScript]):
    targets = ()

    async def modify(self, resource: Resource, config: UserScript) -> None:
        script_globals = dict()
        script_locals = dict()
        exec(config.code, script_globals, script_locals)

        if "main" in script_globals:
            script_main = script_globals["main"]
        elif "main" in script_locals:
            script_main = script_locals["main"]
        else:
            raise ValueError("No `main` function found in script!")

        from ofrak.ofrak_context import get_current_ofrak_context

        context = get_current_ofrak_context()

        script_main.__globals__.update(script_globals)
        script_main.__globals__.update(script_locals)

        try:
            await script_main(context, *config.args, **config.kwargs)
        except:
            raise


async def example_usage(oc):
    r = await oc.create_root_resource("any", b"")

    with open("/tmp/tinycore_manual_unpack.py") as f:
        code = f.read()

    config = UserScript(code, (), {})
    await r.run(
        RunScriptModifier,
        config,
    )
