"""
Assembler services used to assemble and disassemble code.
"""
from abc import ABCMeta, abstractmethod

from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import InstructionSetMode
from ofrak.service.abstract_ofrak_service import AbstractOfrakService


class AssemblerServiceInterface(AbstractOfrakService):
    """An interface for assembler services."""

    __metaclass__ = ABCMeta

    @abstractmethod
    async def assemble(
        self,
        assembly: str,
        vm_addr: int,
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> bytes:
        """
        Assemble the given assembly code.

        :param str assembly: The assembly to assemble
        :param int vm_addr: The virtual address at which the assembly should be assembled.
        :param ProgramAttributes program_attributes: The processor targeted by the assembly
        :param InstructionSetMode mode: The mode of the processor for the assembly

        :return: The assembled machine code
        """
        raise NotImplementedError
