from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple

from ofrak import Identifier, Resource, Analyzer, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    ElfSymbol,
    ElfSymbolType,
    Elf,
    ProgramAttributes,
    ElfSectionHeader,
    ElfSectionFlag,
    ComplexBlock,
)

from ofrak_type.architecture import InstructionSetMode, InstructionSet
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

    :ivar symbol_type: Type of this symbol, necessary to know how it should be treated when
    linking: code, writable data, and general data
    :ivar mode: Mode of this symbol, only relevant if it is code (FUNC) and the architecture has
    multiple possible modes which need to be handled by the linker (e.g. ARM Thumb interworking)
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


class ElfLinkableSymbolIdentifier(Identifier[None]):
    """
    ElfSymbols are linkable, so tag them as LinkableSymbols.
    """

    targets = (ElfSymbol,)

    async def identify(self, resource: Resource, config: None) -> None:
        elf_sym = await resource.view_as(ElfSymbol)
        if elf_sym.st_shndx == 0 or elf_sym.st_shndx >= 0xFF00:
            return
        if elf_sym.symbol_index == 0:
            return
        if elf_sym.st_name == 0:
            return
        if elf_sym.get_type() not in [ElfSymbolType.FUNC, ElfSymbolType.OBJECT]:
            return
        resource.add_tag(LinkableSymbol)


class ElfLinkableSymbolAnalyzer(Analyzer[None, LinkableSymbol]):
    """
    Extract the linking info relevant for OFRAK's PatchMaker.
    """

    targets = (ElfSymbol,)
    outputs = (LinkableSymbol,)

    async def analyze(self, resource: Resource, config: None) -> LinkableSymbol:
        elf_symbol = await resource.view_as(ElfSymbol)
        elf_r = await resource.get_only_ancestor(ResourceFilter(tags=(Elf,)))
        prog_attrs = await elf_r.analyze(ProgramAttributes)

        sym_name = await elf_symbol.get_name()
        if elf_symbol.get_type() is ElfSymbolType.FUNC:
            sym_type = LinkableSymbolType.FUNC
        elif elf_symbol.get_type() is ElfSymbolType.OBJECT:
            # Need to check what section it is in to see if it is writable
            section_containing_symbol = await elf_r.get_only_descendant_as_view(
                ElfSectionHeader,
                r_filter=ResourceFilter(
                    tags=(ElfSectionHeader,),
                    attribute_filters=(
                        ResourceAttributeValueFilter(
                            ElfSectionHeader.SectionIndex, elf_symbol.st_shndx
                        ),
                    ),
                ),
            )
            if section_containing_symbol.has_flag(ElfSectionFlag.WRITE):
                sym_type = LinkableSymbolType.RW_DATA
            else:
                sym_type = LinkableSymbolType.RO_DATA
        else:
            raise ValueError(
                f"Cannot analyze LinkableSymbol for {sym_name} because it has unsupported "
                f"ElfSymbolType {elf_symbol.get_type().name} (only type FUNC and OBJECT) are "
                f"supported for auto-analysis). ElfLinkableSymbolIdentifier should have already "
                f"filtered this out; was this resource erroneously manually tagged as a "
                f"LinkableSymbol?"
            )

        sym_mode = InstructionSetMode.NONE
        sym_vaddr = elf_symbol.st_value

        # Check if this is a THUMB function symbol
        if prog_attrs.isa is InstructionSet.ARM and sym_type is LinkableSymbolType.FUNC:
            if elf_symbol.st_value & 0x1:
                sym_mode = InstructionSetMode.THUMB
                sym_vaddr = elf_symbol.st_value - 1

        return LinkableSymbol(sym_vaddr, sym_name, sym_type, sym_mode)


class ComplexBlockLinkableSymbolIdentifier(Identifier[None]):
    """
    ComplexBlocks are linkable, so tag them as LinkableSymbols.
    """

    targets = (ComplexBlock,)

    async def identify(self, resource: Resource, config: None) -> None:
        cb = await resource.view_as(ComplexBlock)

        if cb.name == "":
            return
        try:
            _ = await cb.get_mode()
        except ValueError:
            # If a ComplexBlock's mode is ambiguous, for any reason, do no extract linkable
            # symbols from it
            return

        resource.add_tag(LinkableSymbol)


class ComplexBlockSymbolAnalyzer(Analyzer[None, LinkableSymbol]):
    targets = (ComplexBlock,)
    outputs = (LinkableSymbol,)

    async def analyze(self, resource: Resource, config: None) -> LinkableSymbol:
        cb = await resource.view_as(ComplexBlock)
        cb_mode = await cb.get_mode()

        return LinkableSymbol(
            cb.virtual_address,
            cb.name,
            LinkableSymbolType.FUNC,
            cb_mode,
        )


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
