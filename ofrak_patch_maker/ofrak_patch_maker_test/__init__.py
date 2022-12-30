import os
from dataclasses import dataclass

from ofrak_type import ArchInfo
from ofrak_patch_maker.toolchain.version import ToolchainVersion

CURRENT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))


@dataclass
class ToolchainUnderTest:
    toolchain_version: ToolchainVersion
    proc: ArchInfo
    extension: str
