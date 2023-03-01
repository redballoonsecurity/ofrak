from ofrak.component.analyzer import Analyzer
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol, LinkableSymbolType
from ofrak.resource import Resource


class ComplexBlockSymbolAnalyzer(Analyzer[None, LinkableSymbol]):
    targets = (ComplexBlock,)
    outputs = (LinkableSymbol,)

    async def analyze(self, resource: Resource, config: None) -> LinkableSymbol:
        cb = await resource.view_as(ComplexBlock)
        cb_mode = await cb.get_mode()

        return LinkableSymbol(
            cb.VirtualAddress,
            cb.Symbol,
            LinkableSymbolType.FUNC,
            cb_mode,
        )
