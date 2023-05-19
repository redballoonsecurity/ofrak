import inspect
from dataclasses import dataclass, field
from typing import Tuple, Dict, Optional

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource


@dataclass
class UserScript(ComponentConfig):
    code: str
    function_name: str = "main"
    args: Tuple[str, ...] = ()
    kwargs: Dict[str, str] = field(default_factory=dict)


class RunScriptModifier(Modifier[UserScript]):
    targets = ()

    async def modify(self, resource: Resource, config: UserScript) -> None:
        script_globals = dict()
        script_locals = dict()
        exec(config.code, script_globals, script_locals)

        if config.function_name in script_globals:
            script_main = script_globals[config.function_name]
        elif config.function_name in script_locals:
            script_main = script_locals[config.function_name]
        else:
            raise ValueError(f"No `{config.function_name}` function found in script!")

        from ofrak.ofrak_context import get_current_ofrak_context, OFRAKContext

        # expect function in script to have signature like:
        # foo(ofrak_context: OFRAKContext, <anything>, root_resource: Optional[Resource] = None):

        script_main_signature = inspect.getfullargspec(script_main)
        assert script_main_signature.annotations[script_main_signature.args[0]] == OFRAKContext
        assert "root_resource" in script_main_signature.args
        assert script_main_signature.annotations["root_resource"] == Optional[Resource]

        context = get_current_ofrak_context()

        script_main.__globals__.update(script_globals)
        script_main.__globals__.update(script_locals)

        try:
            await script_main(
                ofrak_context=context, *config.args, **config.kwargs, root_resource=resource
            )
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
