from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Tuple, Iterable

from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    InstructionSetMode,
    ProcessorType,
)
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness


@dataclass
class DisassemblerServiceRequest:
    isa: InstructionSet
    sub_isa: Optional[SubInstructionSet]
    bit_width: BitWidth
    endianness: Endianness
    processor: Optional[ProcessorType]
    mode: InstructionSetMode
    data: bytes
    virtual_address: int


@dataclass
class DisassemblyResult:
    address: int
    size: int
    mnemonic: str
    operands: str


@dataclass
class RegisterUsageResult:
    regs_read: Tuple[str, ...]
    regs_written: Tuple[str, ...]


class DisassemblerServiceInterface(AbstractOfrakService, ABC):
    @abstractmethod
    async def disassemble(self, request: DisassemblerServiceRequest) -> Iterable[DisassemblyResult]:
        raise NotImplementedError

    @abstractmethod
    async def get_register_usage(self, request: DisassemblerServiceRequest) -> RegisterUsageResult:
        raise NotImplementedError


class DisassemblerArchSupportError(Exception):
    pass


class DisassemblerRegisterUsageSupportError(Exception):
    pass
