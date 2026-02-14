from dataclasses import dataclass
from typing import Optional, Tuple

from ofrak.model.resource_model import ResourceAttributes

from ofrak_type.architecture import ArchInfo


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ProgramAttributes(ResourceAttributes, ArchInfo):
    """
    Analyzer output containing architecture attributes of a program.

    :ivar entry_points: program entry point virtual addresses (first is the main entry)
    :ivar base_address: preferred load address / image base, or None if unknown
    """

    entry_points: Tuple[int, ...] = ()
    base_address: Optional[int] = None
