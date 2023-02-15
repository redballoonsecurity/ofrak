from dataclasses import dataclass
from typing import Dict

from ofrak.component.analyzer import Analyzer
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.patch_maker.linkable_binary import LinkableBinary
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol, LinkableSymbolType
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak_type.error import NotFoundError


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


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class LinkableBinaryAttributes(ResourceAttributes):
    patched_symbols: Dict[str, int]


@dataclass
class LinkableBinaryAnalyzerConfig(ComponentConfig):
    patched_symbols: Dict[str, int]


class LinkableBinaryAnalyzer(Analyzer[LinkableBinaryAnalyzerConfig, LinkableBinaryAttributes]):
    """
    Analyze a LinkableBinary and return all symbols that have been defined in previously applied
    patches.
    """

    targets = (LinkableBinary,)
    outputs = (LinkableBinaryAttributes,)

    async def analyze(
        self, resource: Resource, config: LinkableBinaryAnalyzerConfig
    ) -> LinkableBinaryAttributes:
        try:
            symbols = resource.get_attributes(LinkableBinaryAttributes).patched_symbols
        except NotFoundError:
            symbols = {}
        symbols.update(config.patched_symbols)
        return LinkableBinaryAttributes(symbols)
