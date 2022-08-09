import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple, Iterable

from ofrak.resource import Resource

from ofrak.component.analyzer import Analyzer
from ofrak.component.unpacker import Unpacker
from ofrak.core.addressable import Addressable
from ofrak_type.architecture import InstructionSetMode
from ofrak.core.basic_block import BasicBlock
from ofrak.core.data import DataWord
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.resource_model import ResourceAttributes, index
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ComplexBlockDataReferenceAttributes(ResourceAttributes):
    referenced_data_vm_addresses: Tuple[int, ...]


@dataclass
class ComplexBlock(MemoryRegion):
    """
    A collection of [basic blocks][ofrak.core.basic_block.BasicBlock] and
    [data words][ofrak.core.data.DataWord] that represent a logical unit of code (usually a
    function).

    :ivar virtual_address: the lowest virtual address in the complex block
    :ivar size: the size of the complex block
    :ivar name: the complex block's name
    """

    name: str

    @index
    def Symbol(self) -> str:
        return self.name

    @classmethod
    def caption(cls, all_attributes) -> str:
        try:
            cb_attributes = all_attributes[ComplexBlock.attributes_type]
            addressable_attributes = all_attributes[Addressable.attributes_type]
        except KeyError:
            return super().caption(all_attributes)
        return f"{hex(addressable_attributes.virtual_address)}: {cb_attributes.name}"

    async def get_basic_blocks(self) -> Iterable[BasicBlock]:
        """
        Get complex block's basic blocks.

        :return: basic blocks
        """
        return await self.resource.get_descendants_as_view(
            BasicBlock,
            r_filter=ResourceFilter.with_tags(BasicBlock),
            r_sort=ResourceSort(Addressable.VirtualAddress),
        )

    async def get_assembly(self) -> str:
        """
        Get the complex block's instructions as an assembly string.

        :return: the complex block's assembly
        """
        bbs = await self.get_basic_blocks()
        bb_assemblies = [bb_r.get_assembly() for bb_r in bbs]
        return "\n".join(await asyncio.gather(*bb_assemblies))

    async def get_data_words(self) -> Iterable[DataWord]:
        """
        Get the complex block's [data words][ofrak.core.data.DataWord].

        :return: the data words in the complex block
        """
        return await self.resource.get_descendants_as_view(
            DataWord,
            r_filter=ResourceFilter.with_tags(DataWord),
            r_sort=ResourceSort(Addressable.VirtualAddress),
        )

    async def get_mode(self) -> InstructionSetMode:
        """
        Get the complex block's [mode][ofrak_type.architecture.InstructionSetMode].

        :raises ValueError: if the basic blocks in the complex block have more than one mode
        :return: the mode of the complex block
        """
        await self.resource.unpack()
        bb_modes = {bb.mode for bb in await self.get_basic_blocks()}
        if len(bb_modes) == 1:
            return bb_modes.pop()
        elif len(bb_modes) > 1:
            raise ValueError(
                f"Multiple modes present in complex block! Not all basic blocks have "
                f"the same mode; found modes {bb_modes}"
            )
        else:
            raise ValueError("No basic blocks found in complex block! Perhaps it was not unpacked")


class ComplexBlockStructureError(RuntimeError):
    pass


class ComplexBlockUnpacker(Unpacker[None], ABC):
    """
    Unpack a [complex block][ofrak.core.complex_block.ComplexBlock] into
    [basic blocks][ofrak.core.basic_block.BasicBlock] and [data words][ofrak.core.data.DataWord].
    """

    targets = (ComplexBlock,)
    children = (BasicBlock, DataWord)
    id = b"ComplexBlockUnpacker"

    @abstractmethod
    async def unpack(self, resource: Resource, config=None):
        """
        Unpack a complex block, identifying all of the basic blocks and data words which are a part
        of it.

        The identified basic blocks and data words must be within the previously identified range
        of the complex block. If the analysis engine identifies basic blocks outside of this
        range, those are be ignored - i.e. not unpacked - and the rest of the basic blocks in
        the function are unpacked as usual.
        """
        raise NotImplementedError()


class ComplexBlockAnalyzer(Analyzer[None, ComplexBlock], ABC):
    """
    Analyze a [complex block][ofrak.core.complex_block.ComplexBlock] and extract its virtual
    address, size, and name.
    """

    targets = (ComplexBlock,)
    outputs = (ComplexBlock,)
    id = b"ComplexBlockAnalyzer"

    @abstractmethod
    async def analyze(self, resource: Resource, config=None) -> ComplexBlock:
        """
        Analyze a complex block resource and extract its virtual address, size, and name.

        :param resource: the complex block resource
        :param config:

        :return: the analyzed complex block
        """
        raise NotImplementedError()


class DataRefsAnalyzer(Analyzer[None, Tuple[ComplexBlockDataReferenceAttributes]], ABC):
    """
    Analyze the references a [complex block][ofrak.core.complex_block.ComplexBlock] makes to data
    addresses.
    """

    id = b"DataRefsAnalyzer"
    targets = (ComplexBlock,)
    outputs = (ComplexBlockDataReferenceAttributes,)

    @abstractmethod
    async def analyze(
        self, resource: Resource, config=None
    ) -> Tuple[ComplexBlockDataReferenceAttributes]:
        """
        Analyze the references a complex block resource makes to data addresses

        :param resource: the complex block resource
        :param config:

        :return: The virtual addresses of all the data words referenced by the complex block.
        """
        raise NotImplementedError()
