from ofrak.component.analyzer import Analyzer
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol, LinkableSymbolType
from ofrak.resource import Resource
from ofrak.model.component_model import ComponentConfig


class ComplexBlockSymbolAnalyzer(Analyzer[None, LinkableSymbol]):
    targets = (ComplexBlock,)
    outputs = (LinkableSymbol,)

    def analyze(self, resource: Resource, config: ComponentConfig = None) -> LinkableSymbol:
        cb = resource.view_as(ComplexBlock)
        cb_mode = cb.get_mode()

        return LinkableSymbol(
            cb.VirtualAddress,
            cb.Symbol,
            LinkableSymbolType.FUNC,
            cb_mode,
        )
