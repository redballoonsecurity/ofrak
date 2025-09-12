import os
from dataclasses import dataclass
from typing import Type, Optional

from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_type import ArchInfo

CURRENT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))


@dataclass
class ToolchainUnderTest:
    toolchain: Type[Toolchain]
    proc: ArchInfo
    extension: str
    userspace_dynamic_linker: Optional[str] = None
