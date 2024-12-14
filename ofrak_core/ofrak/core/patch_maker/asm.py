from dataclasses import dataclass
from typing import Type

from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig

from ofrak import Modifier
from ofrak.model.component_model import ComponentConfig


@dataclass
class AssemblyHookModifierConfig(ComponentConfig):
    hook_addr: int
    payload: str
    toolchain_config: ToolchainConfig
    toolchain: Type[Toolchain]


class AssemblyHookModifier(Modifier[AssemblyHookModifierConfig]):
    """
    Hook an arbitrary assembly instruction so that it runs an arbirary payload.

    This modifier will:

    1. Allocate space for the given payload (and restore instruction) in the target binary
    2. Overwrite the instruction at "hook_addr" with a hook to the allocated space
    3. Inject the payload, restore instruction, and branch back.


    Hook an assembly instruction to

    Hook an
    Insert a simple assm

    """
