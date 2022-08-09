import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Iterable

from ofrak.resource import Resource

from ofrak.component.analyzer import Analyzer
from ofrak.component.unpacker import Unpacker
from ofrak.core.addressable import Addressable
from ofrak_type.architecture import InstructionSetMode
from ofrak.core.instruction import Instruction
from ofrak.core.memory_region import MemoryRegion
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort, ResourceSortDirection


@dataclass
class BasicBlock(MemoryRegion):
    """
    A collection of [instructions][ofrak.core.instruction.Instruction] that constitute a single
    block of code with one entry point and one exit point.

    :ivar virtual_address: the virtual address corresponding ot the start of the basic block
    :ivar size: the basic block's size (the difference between the virtual address immediately after
    the block's last instruction and the block's virtual address)
    :ivar mode: the instruction set mode of the basic block
    :ivar is_exit_point: true if the basic block is the exit point of a function; if so,
    then exit_vaddr is None
    :ivar exit_vaddr: the virtual address of the next basic block (if the current basic block is
    not an exit point)
    """

    mode: InstructionSetMode
    is_exit_point: bool
    exit_vaddr: Optional[int]

    @classmethod
    def caption(cls, all_attributes) -> str:
        return str(cls.__name__)

    async def get_instructions(self) -> Iterable[Instruction]:
        """
        Get the basic block's [instructions][ofrak.core.instruction.Instruction].

        :return: the instructions in the basic block
        """
        return await self.resource.get_descendants_as_view(
            Instruction,
            r_filter=ResourceFilter.with_tags(Instruction),
            r_sort=ResourceSort(Addressable.VirtualAddress, ResourceSortDirection.ASCENDANT),
        )

    async def get_assembly(self) -> str:
        """
        Get the basic block's instructions as an assembly string.

        :return: the basic block's assembly
        """
        instructions = await self.get_instructions()
        instruction_assemblies = [i.get_assembly() for i in instructions]
        return "\n".join(await asyncio.gather(*instruction_assemblies))


class BasicBlockUnpacker(Unpacker[None], ABC):
    """
    Unpack a [basic block][ofrak.core.basic_block.BasicBlock] into
    [instructions][ofrak.core.instruction.Instruction].
    """

    id = b"BasicBlockUnpacker"
    targets = (BasicBlock,)
    children = (Instruction,)

    @abstractmethod
    async def unpack(self, resource: Resource, config=None):
        """
        Unpack a basic block into its corresponding instructions.
        """
        raise NotImplementedError()


class BasicBlockAnalyzer(Analyzer[None, BasicBlock], ABC):
    """
    Analyze a [basic block][ofrak.core.basic_block.BasicBlock] and extract its virtual address,
    size, mode, whether it is an exit point, and exit_vaddr.
    """

    targets = (BasicBlock,)
    outputs = (BasicBlock,)
    id = b"BasicBlockAnalyzer"

    @abstractmethod
    async def analyze(self, resource: Resource, config=None) -> BasicBlock:
        """
        Analyze a basic block and extract its virtual address, size, mode, whether it is an
        exit point, and exit_vaddr.

        :param resource: the basic block resource
        :param config:

        :return: the analyzed basic block
        """
        raise NotImplementedError()
