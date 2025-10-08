from ofrak.component.analyzer import Analyzer
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol, LinkableSymbolType
from ofrak.resource import Resource
from ofrak.model.component_model import ComponentConfig


class ComplexBlockSymbolAnalyzer(Analyzer[None, LinkableSymbol]):
    """
    Analyzes function blocks (complex blocks) to identify and extract linkable symbols by examining function entry points, call relationships, and debug information. Creates symbol entries with names and addresses that can be used for linking or reference. Use when analyzing disassembled functions to discover callable symbol names and addresses, build a symbol table for stripped binaries, or prepare for code injection that needs to reference existing functions. Helpful for understanding what functions are available to call.
    """

    targets = (ComplexBlock,)
    outputs = (LinkableSymbol,)

    async def analyze(self, resource: Resource, config: ComponentConfig = None) -> LinkableSymbol:
        cb = await resource.view_as(ComplexBlock)
        cb_mode = await cb.get_mode()

        return LinkableSymbol(
            cb.VirtualAddress,
            cb.Symbol,
            LinkableSymbolType.FUNC,
            cb_mode,
        )
