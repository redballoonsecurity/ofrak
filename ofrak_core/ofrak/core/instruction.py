from abc import ABC
from dataclasses import dataclass
from typing import Optional, Tuple


from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import index, ResourceAttributes
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.assembler.assembler_service_i import AssemblerServiceInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak_type.architecture import InstructionSetMode
from ofrak_type.range import Range


@dataclass
class Instruction(MemoryRegion):
    """
    A single ISA instruction.

    :ivar virtual_address: the virtual address of the start of the instruction
    :ivar size: the size of the instruction
    :ivar disassembly: the instruction's disassembly
    :ivar mnemonic: the instruction's mnemonic
    :ivar operands: the instruction's operands
    :ivar mode: the instruction set mode of the instruction
    """

    disassembly: str
    mnemonic: str
    operands: str
    mode: InstructionSetMode

    @index
    def Mnemonic(self) -> str:
        return self.mnemonic

    @classmethod
    def caption(cls, all_attributes) -> str:
        try:
            instruction_attributes = all_attributes[Instruction.attributes_type]
        except KeyError:
            return super().caption(all_attributes)
        return f"{instruction_attributes.mnemonic} {instruction_attributes.operands}"

    async def get_assembly(self) -> str:
        """
        Get the instruction as an assembly string.

        :return: the instruction as an assembly string
        """
        return f"{self.mnemonic} {self.operands}"

    async def modify_assembly(
        self,
        mnemonic: Optional[str] = None,
        operands: Optional[str] = None,
        mode: Optional[InstructionSetMode] = None,
    ) -> bytes:
        """
        Modify the instruction, changing it to an instruction of equal size.

        :param mnemonic: the modified instruction mnemonic
        :param operands: the modified instruction operands
        :param mode: the modified instruction's instruction set mode

        :return: the instruction's machine code after modification
        """
        modification_config = InstructionModifierConfig(
            mnemonic or self.mnemonic,
            operands or self.operands,
            mode or self.mode,
        )
        await self.resource.run(InstructionModifier, modification_config)
        data_after_modification = await self.resource.get_data()

        return data_after_modification


@dataclass
class RegisterUsage(ResourceAttributes):
    """
    Information about the register usage in a Resource containing some assembly, such as an
    Instruction.

    :ivar registers_read: registers read from when the assembly executes
    :ivar registers_written: registers written to when the assembly executes
    """

    registers_read: Tuple[str, ...]
    registers_written: Tuple[str, ...]


class InstructionAnalyzer(Analyzer[None, Instruction], ABC):
    """
    Analyze an [instruction][ofrak.core.instruction.Instruction] and extract its attributes.
    """

    id = b"InstructionAnalyzer"
    targets = (Instruction,)
    outputs = (Instruction,)


class InstructionRegisterUsageAnalyzer(Analyzer[None, RegisterUsage], ABC):
    """
    Analyze an [instruction][ofrak.core.instruction.Instruction] and extract the list of registers
    read and written.
    """

    id = b"InstructionRegisterUsageAttributesAnalyzer"
    targets = (Instruction,)
    outputs = (RegisterUsage,)


@dataclass
class InstructionModifierConfig(ComponentConfig):
    """
    Config for the [InstructionModifier][ofrak.core.instruction.InstructionModifier].

    :ivar mnemonic: the modified instruction's mnemonic
    :ivar operands: the modified instruction's operands
    :ivar mode: the modified instruction's instruction set mode
    """

    mnemonic: str
    operands: str
    mode: InstructionSetMode


class InstructionModifier(Modifier[InstructionModifierConfig]):
    """
    Modify an instruction.
    """

    targets = (Instruction,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        assembler_service: AssemblerServiceInterface,
    ):
        super().__init__(
            resource_factory,
            data_service,
            resource_service,
        )
        self._assembler_service = assembler_service

    async def modify(self, resource: Resource, config: InstructionModifierConfig):
        """
        Modify an instruction.

        :param resource: the instruction resource to modify
        :param config:

        :raises AssertionError: if the modified instruction length does not match the length of
        the original instruction
        """
        resource_memory_region = await resource.view_as(MemoryRegion)

        modified_assembly = f"{config.mnemonic} {config.operands}"

        asm = await self._assembler_service.assemble(
            modified_assembly,
            resource_memory_region.virtual_address,
            await resource.analyze(ProgramAttributes),
            config.mode,
        )
        assert (
            len(asm) == resource_memory_region.size
        ), "The modified instruction length does not match the original instruction length"

        new_attributes = Instruction.attributes_type(  # type: ignore
            disassembly=modified_assembly,
            mnemonic=config.mnemonic,
            operands=config.operands,
            mode=config.mode,
        )
        resource.queue_patch(Range.from_size(0, len(asm)), asm)
        resource.add_attributes(new_attributes)
