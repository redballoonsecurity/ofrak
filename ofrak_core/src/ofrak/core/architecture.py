from dataclasses import dataclass
from typing import Optional, Tuple

from ofrak.model.resource_model import ResourceAttributes

from ofrak_type.architecture import ArchInfo


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ProgramAttributes(ResourceAttributes, ArchInfo):
    """
    Analyzer output containing architecture attributes of a program.

    :ivar entry_points: Virtual addresses that are program entry points. The first entry is
        typically the main entry point. Multiple entries support formats like DLLs with
        DllMain + exports, or firmware with reset vectors.
    :ivar base_address: Preferred load address / image base where the program expects to be
        loaded. This is the intended load address from the binary format (e.g., ELF's first
        PT_LOAD segment vaddr, PE's ImageBase). Backends may use this for PIE handling and
        address rebasing.
    """

    entry_points: Tuple[int, ...] = ()
    base_address: Optional[int] = None
