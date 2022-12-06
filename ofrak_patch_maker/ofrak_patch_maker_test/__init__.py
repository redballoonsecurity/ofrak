import os
from dataclasses import dataclass
from ofrak.core.architecture import ProgramAttributes

CURRENT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))


@dataclass
class ToolchainUnderTest:
    toolchain: type
    proc: ProgramAttributes
    extension: str
