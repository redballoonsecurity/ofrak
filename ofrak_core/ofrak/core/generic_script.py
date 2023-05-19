from dataclasses import dataclass, field
from typing import Any, Dict, Union

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource

_PrimitiveType = Union[int, bool, str, float, bytes]


@dataclass
class RunScriptModifierConfig(ComponentConfig):
    """
    Specification of some Python code to run in the current OFRAK context. Useful for reusing quick
    helper functions and the like.

    :ivar code: Python source code defining one or more function which take an OFRAKContext and
    Resource as arguments.
    :ivar function_name: Name of the function to run.
    :ivar extra_args: Extra arguments to pass to the function in key-value form.
    """

    code: str
    function_name: str = "main"
    extra_args: Dict[str, _PrimitiveType] = field(default_factory=dict)


class RunScriptModifier(Modifier[RunScriptModifierConfig]):
    """
    "Import" and run Python functions in the current OFRAK context. Useful for reusing quick
    helper functions and the like. Since this can be run through the GUI, it can be used to
    automate tasks which might be repetitive or impossible purely through the graphical interface.

    """

    targets = ()

    async def modify(self, resource: Resource, config: RunScriptModifierConfig) -> None:
        script_globals: Dict[str, Any] = dict()
        script_locals: Dict[str, Any] = dict()
        exec(config.code, script_globals, script_locals)

        if config.function_name in script_globals:
            script_main = script_globals[config.function_name]
        elif config.function_name in script_locals:
            script_main = script_locals[config.function_name]
        else:
            raise ValueError(f"No `{config.function_name}` function found in script!")

        from ofrak.ofrak_context import get_current_ofrak_context

        context = get_current_ofrak_context()

        script_main.__globals__.update(script_globals)
        script_main.__globals__.update(script_locals)

        full_kwargs: Dict[str, Any] = {
            "ofrak_context": context,
            "root_resource": resource,
        }
        full_kwargs.update(config.extra_args)

        await script_main(**full_kwargs)
