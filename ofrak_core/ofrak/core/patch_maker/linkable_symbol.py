from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple

from ofrak_type.architecture import InstructionSetMode
from ofrak.core.label import LabeledAddress
from ofrak_patch_maker.toolchain.model import Segment
from ofrak_type.memory_permissions import MemoryPermissions


class LinkableSymbolType(Enum):
    FUNC = 0
    RW_DATA = 1
    RO_DATA = 2
    UNDEF = -1


@dataclass
class LinkableSymbolStubInfo:
    """
    Container holding the information needed to create a stub for a LinkableSymbol.

    :var asm_prefixes: The lines to prefix an assembly stub for this symbol, usually describing
    what type of symbol this is and optionally the mode
    :var segments: Segments to extract from the stub object file.
    """

    asm_prefixes: List[str]
    segments: Tuple[Segment, ...]


@dataclass
class LinkableSymbol(LabeledAddress):
    """
    A 'symbol' in the binary that may be used for the purpose of linking when injecting a patch.
    It may be extracted from symbol information that was already in the binary, added manually,
    or inferred by some analysis.
    """

    symbol_type: LinkableSymbolType
    mode: InstructionSetMode = InstructionSetMode.NONE

    def get_stub_info(self) -> LinkableSymbolStubInfo:
        """
        Get the information about this LinkableSymbol needed to generate a stub
        """
        if self.symbol_type is LinkableSymbolType.FUNC:
            return _make_rx_stub_info(self.name, self.virtual_address, self.mode)

        elif self.symbol_type is LinkableSymbolType.RO_DATA:
            return _make_r_stub_info(self.name, self.virtual_address)

        elif self.symbol_type is LinkableSymbolType.RW_DATA:
            return _make_rw_stub_info(self.name, self.virtual_address)

        else:
            raise NotImplementedError(f"No stub info factory for {self.symbol_type.name}")


def _make_rx_stub_info(name: str, vaddr: int, mode: InstructionSetMode) -> LinkableSymbolStubInfo:
    asm_prefixes = [".section .text", f".type {name}, %function"]
    if mode is InstructionSetMode.THUMB:
        asm_prefixes.append(".thumb")
    segments = (
        # Executable stub goes in .text segment
        Segment(
            segment_name=".text",
            vm_address=vaddr,
            offset=0,
            is_entry=False,
            length=0,
            access_perms=MemoryPermissions.RX,
        ),
        # Null segments required for unused .data
        Segment(
            segment_name=".data",
            vm_address=0,
            offset=0,
            is_entry=False,
            length=0,
            access_perms=MemoryPermissions.RW,
        ),
    )
    return LinkableSymbolStubInfo(asm_prefixes, segments)


def _make_r_stub_info(name: str, vaddr: int) -> LinkableSymbolStubInfo:
    asm_prefixes = [".section .rodata", f".type {name}, %object"]
    segments = (
        # Read-only symbol goes in .rodata segment
        Segment(
            segment_name=".rodata",
            vm_address=vaddr,
            offset=0,
            is_entry=False,
            length=0,
            access_perms=MemoryPermissions.R,
        ),
        # Null segments required for unused .text and .data
        Segment(
            segment_name=".text",
            vm_address=0,
            offset=0,
            is_entry=False,
            length=0,
            access_perms=MemoryPermissions.RX,
        ),
        Segment(
            segment_name=".data",
            vm_address=0,
            offset=0,
            is_entry=False,
            length=0,
            access_perms=MemoryPermissions.RW,
        ),
    )
    return LinkableSymbolStubInfo(asm_prefixes, segments)


def _make_rw_stub_info(name: str, vaddr: int) -> LinkableSymbolStubInfo:
    asm_prefixes = [".section .data", f".type {name}, %object"]
    segments = (
        # Read-write symbol goes in .data segment
        Segment(
            segment_name=".data",
            vm_address=vaddr,
            offset=0,
            is_entry=False,
            length=0,
            access_perms=MemoryPermissions.RW,
        ),
        # Null segment required for unused .text
        Segment(
            segment_name=".text",
            vm_address=0,
            offset=0,
            is_entry=False,
            length=0,
            access_perms=MemoryPermissions.RX,
        ),
    )
    return LinkableSymbolStubInfo(asm_prefixes, segments)
