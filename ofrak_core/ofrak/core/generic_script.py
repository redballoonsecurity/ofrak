import inspect
from dataclasses import dataclass
from typing import Tuple, Dict, Optional

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource


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
        exec(config.code[0][1], script_globals, script_locals)

        if "main" in script_globals:
            script_main = script_globals["main"]
        elif "main" in script_locals:
            script_main = script_locals["main"]
        else:
            raise ValueError("No `main` function found in script!")

        from ofrak.ofrak_context import get_current_ofrak_context, OFRAKContext

        # expect main function in script to have signature like:
        # main(ofrak_context: OFRAKContext, <anything>, root_resource: Optional[Resource] = None):

        script_main_signature = inspect.getfullargspec(script_main)
        assert script_main_signature.annotations[script_main_signature.args[0]] == OFRAKContext
        assert "root_resource" in script_main_signature.args
        assert script_main_signature.annotations["root_resource"] == Optional[Resource]

        context = get_current_ofrak_context()

        script_main.__globals__.update(script_globals)
        script_main.__globals__.update(script_locals)

        try:
            await script_main(context, *config.args, **config.kwargs, root_resource=resource)
        except:
            raise


async def example_usage(oc):
    r = await oc.create_root_resource("any", b"")

    with open("/transfer/test_script.py") as f:
        code = f.read()

    config = UserScript(code, (), {})
    await r.run(
        RunScriptModifier,
        config,
    )
