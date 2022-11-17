import dataclasses
import logging
import os
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

from ofrak.component.modifier import Modifier
from ofrak.core.binary import GenericBinary
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol, LinkableSymbolType
from ofrak.model.component_model import ComponentConfig, CLIENT_COMPONENT_ID
from ofrak.resource import Resource
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceAttributeValueFilter,
)
from ofrak_patch_maker.model import BOM, PatchRegionConfig
from ofrak_patch_maker.toolchain.model import Segment
from ofrak_type.error import NotFoundError

LOGGER = logging.getLogger()


class SymbolExistsError(RuntimeError):
    pass


@dataclass
class LinkableBinary(GenericBinary):
    """
    A resource with accompanying metadata which provide a mapping
    between symbols, and their corresponding offset and type within the program.
    """

    async def get_only_symbol(
        self, *, name: Optional[str] = None, vaddr: Optional[int] = None
    ) -> LinkableSymbol:
        """
        Get exactly one LinkableSymbol from this LinkableBinary matching a given name,
        virtual address, or both. If values for both vaddr and name are specified, only finds
        symbols which match both vaddr AND name, not vaddr OR name.

        :param name: Name of the symbol to look for.
        :param vaddr: Virtual address of the symbol to look for.

        :return: The only LinkableSymbol with the given name and/or vaddr.

        :raises ValueError: if both `name` and `vaddr` arguments are None.
        :raises NotFoundError: if no symbol or more than one is found with name and/or vaddr.
        """
        attributes_filters = []
        if name is None and vaddr is None:
            raise ValueError("At least one of the arguments name, vaddr must not be None!")
        if vaddr is not None:
            attributes_filters.append(
                ResourceAttributeValueFilter(LinkableSymbol.VirtualAddress, vaddr)
            )
        if name is not None:
            attributes_filters.append(ResourceAttributeValueFilter(LinkableSymbol.Label, name))

        return await self.resource.get_only_descendant_as_view(
            LinkableSymbol,
            r_filter=ResourceFilter(
                tags=(LinkableSymbol,),
                attribute_filters=tuple(attributes_filters),
            ),
        )

    async def get_symbols(
        self, *, name: Optional[str] = None, vaddr: Optional[int] = None
    ) -> Iterable[LinkableSymbol]:
        """
        Get exactly all LinkableSymbols from this LinkableBinary matching a given name,
        virtual address, or both. If values for both vaddr and name are specified, only finds
        symbols which match both vaddr AND name, not vaddr OR name.

        :param name: Name of the symbols to look for.
        :param vaddr: Virtual address of the symbols to look for.

        :return: All LinkableSymbol with the given name and/or vaddr.

        :raises NotFoundError: if no symbols are found with name and/or vaddr.
        """
        attributes_filters = []
        if vaddr is not None:
            attributes_filters.append(
                ResourceAttributeValueFilter(LinkableSymbol.VirtualAddress, vaddr)
            )
        if name is not None:
            attributes_filters.append(ResourceAttributeValueFilter(LinkableSymbol.Label, name))

        symbols_by_name = dict()

        for sym in await self.resource.get_descendants_as_view(
            LinkableSymbol,
            r_filter=ResourceFilter(
                tags=(LinkableSymbol,),
                attribute_filters=tuple(attributes_filters) if attributes_filters else None,
            ),
        ):
            if sym.name in symbols_by_name:
                other_sym = symbols_by_name[sym.name]
                if other_sym == sym:
                    continue
                else:
                    sym_source, _ = _describe_symbol_source(sym)
                    other_sym_source, _ = _describe_symbol_source(other_sym)

                    raise ValueError(
                        f"Multiple symbols with the name {sym.name} found, and they have different "
                        f"information! {sym} ({sym_source}) vs. {other_sym} ({other_sym_source})"
                    )
            symbols_by_name[sym.name] = sym

        return symbols_by_name.values()

    # TODO: Un-stringify PatchMaker; OFRAK imports in PatchMaker results in circular Program imports
    async def make_linkable_bom(
        self,
        patch_maker: "PatchMaker",  # type: ignore
        build_tmp_dir: str,
    ) -> Tuple[BOM, PatchRegionConfig]:
        """
        Build a BOM with all the symbols known to SymbolizedBinary. This BOM can be used to build
        the FEM so that it has access to all those symbols as weak symbols. This BOM in practice
        enables linking against the target binary. Because they are weak symbols, the patch is
        free to redefine any of these symbols - for example, if we are patching in a new body for
        a function, it will not conflict with the existing symbol for that function in the target
        binary.

        We create stubs for symbols rather than treat them purely as symbols because the linker in
        some cases needs a little more information than the symbol alone can provide - ARM/Thumb
        interworking in particular pushed us in this direction. Creating stubs for all symbols is
        simpler than trying to decide whether we need to create a symbol or stub for each symbol
        based on its mode compared to the mode of something we are trying to inject.

        :param patch_maker: PatchMaker instance to use to build the BOM.
        :param build_tmp_dir: A temporary directory to use for the BOM files.

        :return: Tuple consisting of a BOM and PatchConfig representing the weak symbol
        definitions for all LinkableSymbols in the binary, ready to be passed in the `boms`
        argument to PatchMaker.make_fem(...).
        """
        stubs: Dict[str, Tuple[Segment, ...]] = dict()
        for symbol in await self.get_symbols():
            stubs_file = os.path.join(build_tmp_dir, f"stub_{symbol.name}.as")
            stub_info = symbol.get_stub_info()
            stub_body = "\n".join(
                stub_info.asm_prefixes
                + [f".global {symbol.name}", f".weak {symbol.name}", f"{symbol.name}:", ""]
            )

            with open(stubs_file, "w+") as f:
                f.write(stub_body)
            stubs[stubs_file] = stub_info.segments

        stubs_bom = patch_maker.make_bom(
            name="stubs",
            source_list=list(stubs.keys()),
            object_list=[],
            header_dirs=[],
        )
        stubs_object_segments = {
            stubs_bom.object_map[stubs_file].path: stub_segments
            for stubs_file, stub_segments in stubs.items()
        }
        return stubs_bom, PatchRegionConfig("stubs_segments", stubs_object_segments)


@dataclass
class UpdateLinkableSymbolsModifierConfig(ComponentConfig):
    """
    :ivar updated_symbols: LinkableSymbols to add or updated.
    :ivar verify_func_modes: Override the mode of FUNC symbols if there is a ComplexBlock that can
    be checked and whose mode does not match the described LinkableSymbol's type.
    :ivar override_existing_names: Handles the case where a LinkableSymbol already exists with the
    same name as one in updated_symbols, or a ComplexBlock already exists at the same address; if
    this option is True, overwrite it with the new symbol info, if False, raise an error.
    """

    updated_symbols: Tuple[LinkableSymbol, ...]
    verify_func_modes: bool = False
    override_existing_names: bool = True

    def __post_init__(self):
        stripped_symbols = []
        for symbol in self.updated_symbols:
            stripped_symbol = dataclasses.replace(symbol)
            stripped_symbol._resource = None
            stripped_symbols.append(stripped_symbol)
        self.updated_symbols = tuple(stripped_symbols)


class UpdateLinkableSymbolsModifier(Modifier[UpdateLinkableSymbolsModifierConfig]):
    """
    Add or update the LinkableSymbols in a LinkableBinary.

    :raises ValueError: if not all the provided symbols have unique vaddrs.
    """

    targets = (LinkableBinary,)

    async def modify(self, resource: Resource, config: UpdateLinkableSymbolsModifierConfig) -> None:
        for symbol in config.updated_symbols:
            try:
                existing_symbol_with_name = await resource.get_only_descendant_as_view(
                    LinkableSymbol,
                    r_filter=ResourceFilter(
                        tags=(LinkableSymbol,),
                        attribute_filters=(
                            ResourceAttributeValueFilter(LinkableSymbol.Label, symbol.name),
                        ),
                    ),
                )

                if existing_symbol_with_name == symbol:
                    continue
                elif config.override_existing_names:
                    existing_symbol_with_name.resource.add_view(symbol)
                    continue
                else:
                    raise ValueError(
                        f"Symbol name {symbol.name} is duplicated between differing symbol "
                        f"definitions {existing_symbol_with_name} (old) and {symbol}"
                    )
            except NotFoundError:
                pass

            if (
                symbol.symbol_type is LinkableSymbolType.FUNC
                and config.verify_func_modes
                or config.override_existing_names
            ):
                try:
                    for cb in await resource.get_descendants_as_view(
                        ComplexBlock,
                        r_filter=ResourceFilter(
                            tags=(ComplexBlock,),
                            attribute_filters=(
                                ResourceAttributeValueFilter(
                                    ComplexBlock.VirtualAddress, symbol.virtual_address
                                ),
                            ),
                        ),
                    ):
                        if config.verify_func_modes:
                            symbol = dataclasses.replace(symbol, mode=await cb.get_mode())
                        if config.override_existing_names:
                            cb.resource.add_view(dataclasses.replace(cb, name=symbol.name))
                except NotFoundError:
                    if config.verify_func_modes:
                        LOGGER.warning(
                            f"Option `verify_func_modes` was set, but no ComplexBlock exists at "
                            f"address {hex(symbol.virtual_address)} so cannot verify the mode of "
                            f"{symbol}"
                        )
            await resource.create_child_from_view(symbol)


def _describe_symbol_source(sym: LinkableSymbol) -> Tuple[str, bytes]:
    """
    Output a short string describing what defined this symbol, either manual input or automatic
    analysis. Useful for debugging linker problems when using LinkableSymbols.

    :param sym:

    :return: A tuple with the description string and the actual component ID
    """
    sym_source = sym.resource.get_model().get_component_id_by_attributes(
        LinkableSymbol.attributes_type
    )
    if sym_source == CLIENT_COMPONENT_ID:
        sym_source_str = f"defined manually by adding view or attributes in a script"
    elif sym_source == UpdateLinkableSymbolsModifier.id:
        sym_source_str = f"defined manually via {sym_source.decode('ascii')}"
    else:
        sym_source_str = f"analyzed via {sym_source.decode('ascii')}"

    return sym_source_str, sym_source
