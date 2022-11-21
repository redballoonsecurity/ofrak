from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol, LinkableSymbolType

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.elf.model import (
    ElfSymbol,
    ElfSymbolType,
    Elf,
    ElfSectionHeader,
    ElfSectionFlag,
)
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter
from ofrak_type.architecture import InstructionSetMode, InstructionSet


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
