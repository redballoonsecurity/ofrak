import os
from dataclasses import dataclass
from typing import Optional
from ofrak_type import ArchInfo

CURRENT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))


@dataclass
class ToolchainUnderTest:
    toolchain: type
    proc: ArchInfo
    extension: str
    userspace_dynamic_linker: Optional[str] = None
