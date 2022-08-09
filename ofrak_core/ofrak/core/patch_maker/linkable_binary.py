import dataclasses
import logging
import os
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

from ofrak.component.modifier import Modifier
from ofrak.core.addressable import Addressable
from ofrak_type.architecture import InstructionSetMode
from ofrak.core.binary import GenericBinary
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.label import LabeledAddress
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceAttributeValueFilter,
    ResourceAttributeValuesFilter,
)
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbol, LinkableSymbolType
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

        return await self.resource.get_descendants_as_view(
            LinkableSymbol,
            r_filter=ResourceFilter(
                tags=(LinkableSymbol,),
                attribute_filters=tuple(attributes_filters) if attributes_filters else None,
            ),
        )

    async def define_linkable_symbols(
        self, proto_symbols: Dict[str, Tuple[int, LinkableSymbolType]]
    ):
        """
        From some basic info about symbols in this program, create a LinkableSymbol resource for
        each one and get any remaining needed info to do this. Usage is to pass a dictionary that
        defines each symbol like so:
        "symbol_name": (symbol_vaddr, symbol_type)

        :param proto_symbols: Mapping of each symbol name to its known vaddr and symbol type.

        :raises NotFoundError: if a ComplexBlock resource with the indicated vaddr does not exist
        for a provided FUNC symbol.
        """
        symbols = []
        for sym_name, (sym_vaddr, sym_type) in proto_symbols.items():
            mode = InstructionSetMode.NONE
            if sym_type is LinkableSymbolType.FUNC:
                try:
                    cb = await self.resource.get_only_descendant_as_view(
                        ComplexBlock,
                        r_filter=ResourceFilter(
                            tags=(ComplexBlock,),
                            attribute_filters=(
                                ResourceAttributeValueFilter(
                                    ComplexBlock.VirtualAddress, sym_vaddr
                                ),
                            ),
                        ),
                    )
                except NotFoundError:
                    raise NotFoundError(
                        f"No ComplexBlock resource exists at vaddr 0x"
                        f"{sym_vaddr:x}; cannot infer its mode."
                    )
                mode = await cb.get_mode()
            symbols.append(LinkableSymbol(sym_vaddr, sym_name, sym_type, mode))

        await self.resource.run(
            UpdateLinkableSymbolsModifier,
            UpdateLinkableSymbolsModifierConfig(tuple(symbols)),
        )

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
            # if symbol.name in excluded_symbols:
            #     continue
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
    updated_symbols: Tuple[LinkableSymbol, ...]

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
        unhandled_symbols = {symbol.name: symbol for symbol in config.updated_symbols}
        unhandled_vaddrs: Dict[int, LinkableSymbol] = {}
        for symbol in config.updated_symbols:
            if symbol.virtual_address not in unhandled_vaddrs:
                unhandled_vaddrs[symbol.virtual_address] = symbol
            else:
                raise ValueError(
                    f"Too many symbols supplied for address {symbol.virtual_address}! Need "
                    f"exactly one."
                )

        # Overwrite existing ComplexBlock with new LinkableSymbols
        filter_for_cb_by_vaddr = ResourceFilter(
            tags=(ComplexBlock,),
            attribute_filters=(
                ResourceAttributeValuesFilter(
                    ComplexBlock.VirtualAddress,
                    tuple(
                        vaddr
                        for vaddr, symbol in unhandled_vaddrs.items()
                        if symbol.symbol_type is LinkableSymbolType.FUNC
                    ),
                ),
            ),
        )

        try:
            for existing_cb in await resource.get_descendants_as_view(
                ComplexBlock, r_filter=filter_for_cb_by_vaddr
            ):
                symbol = unhandled_vaddrs[existing_cb.virtual_address]
                existing_cb.resource.add_view(symbol)
                # Update the value of the ComplexBlock.name attribute
                existing_cb.resource.add_view(dataclasses.replace(existing_cb, name=symbol.name))
                unhandled_symbols.pop(symbol.name)
        except NotFoundError:
            LOGGER.debug("No existing ComplexBlocks found for the provided symbols, moving on")

        # Overwrite existing LabeledAddress with new LinkableSymbols
        filter_for_label_by_name = ResourceFilter(
            tags=(LabeledAddress,),
            attribute_filters=(
                ResourceAttributeValuesFilter(
                    LabeledAddress.Label, tuple(unhandled_symbols.keys())
                ),
            ),
        )
        try:
            for existing_label in await resource.get_descendants_as_view(
                LabeledAddress,
                r_filter=filter_for_label_by_name,
            ):
                if existing_label.name not in unhandled_symbols:
                    raise SymbolExistsError(
                        f"Multiple LabeledAddress resources with name {existing_label.name}!"
                    )
                existing_label.resource.add_view(unhandled_symbols.pop(existing_label.name))
        except NotFoundError:
            LOGGER.debug("No existing LabeledAddresses found for the provided symbols, moving on")

        # Overwrite existing Addressables with new LinkableSymbols
        # Only do this for LinkableSymbols which did not override existing LabeledAddress above
        unhandled_vaddrs = {symbol.virtual_address: symbol for symbol in unhandled_symbols.values()}

        filter_for_label_by_vaddr = ResourceFilter(
            tags=(Addressable,),
            attribute_filters=(
                ResourceAttributeValuesFilter(
                    Addressable.VirtualAddress, tuple(unhandled_vaddrs.keys())
                ),
            ),
        )

        try:
            for existing_addressable in await resource.get_descendants_as_view(
                Addressable,
                r_filter=filter_for_label_by_vaddr,
            ):
                symbol = unhandled_vaddrs[existing_addressable.virtual_address]
                existing_addressable.resource.add_view(symbol)
                unhandled_symbols.pop(symbol.name)
        except NotFoundError:
            LOGGER.debug("No existing Addressable found for the provided symbols, moving on")

        # For any new LinkableSymbols that we could not add to existing resources, create a new
        # resource
        for symbol in unhandled_symbols.values():
            await resource.create_child_from_view(symbol)
