from ofrak.component.identifier import Identifier
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol
from ofrak.resource import Resource


class LinkableSymbolIdentifier(Identifier):
    """
    Component to identify Complex Blocks as Linkable Symbols. If this component is discovered,
    it will tag all [ComplexBlock][ofrak.core.complex_block.ComplexBlock]s as LinkableSymbols.
    """

    id = b"LinkableSymbolIdentifier"
    targets = (ComplexBlock,)

    async def identify(self, resource: Resource, config=None):
        resource.add_tag(LinkableSymbol)
