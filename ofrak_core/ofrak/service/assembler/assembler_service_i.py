"""
Assembler services used to assemble and disassemble code.
"""
from abc import ABCMeta, abstractmethod
from typing import Iterable, AsyncIterator

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

    async def assemble_many(
        self,
        assembly_list: Iterable[str],
        vm_addrs: Iterable[int],
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> AsyncIterator[bytes]:
        raise NotImplementedError
        # Necessary for mypy to recognize this function as a generator, even though this never runs
        yield

    @abstractmethod
    async def assemble_file(
        self,
        assembly_file: str,
        vm_addr: int,
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> bytes:
        """
        Assemble the given assembly file.

        :param str assembly_file: The path to the assembly file.
        :param int vm_addr: The virtual address at which the assembly file should be assembled.
        :param ProgramAttributes program_attributes: The processor targeted by the assembly
        :param InstructionSetMode mode: The mode of the processor for the assembly

        :return: The assembled machine code
        """
        raise NotImplementedError

    @abstractmethod
    async def assemble_files(
        self,
        assembly_files: Iterable[str],
        vm_addrs: Iterable[int],
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> AsyncIterator[bytes]:
        """
        Assemble the given assembly files.

        :param Iterable[str] assembly_files: The path to the assembly file.
        :param Iterable[int] vm_addrs: The virtual address at which the assembly file should be
        assembled.
        :param ProgramAttributes program_attributes: The processor targeted by the assembly
        :param InstructionSetMode mode: The mode of the processor for the assembly

        :return: The assembled machine code
        """
        raise NotImplementedError
        # Necessary for mypy to recognize this function as a generator, even though this never runs
        yield
