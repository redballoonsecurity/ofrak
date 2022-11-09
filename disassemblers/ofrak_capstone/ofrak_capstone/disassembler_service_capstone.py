import logging
import re
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, Iterable

from capstone import (
    Cs,
    CS_ARCH_ARM64,
    CS_ARCH_ARM,
    CS_ARCH_X86,
    CS_ARCH_PPC,
    CS_ARCH_MIPS,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    CS_MODE_ARM,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_16,
    CsError,
)

from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    InstructionSetMode,
    ProcessorType,
)
from ofrak.service.disassembler.disassembler_service_i import (
    DisassemblerServiceInterface,
    DisassemblerServiceRequest,
    DisassemblyResult,
    RegisterUsageResult,
    DisassemblerRegisterUsageSupportError,
    DisassemblerArchSupportError,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness


@dataclass(frozen=True)
class CapstoneDisassemblerType:
    isa: InstructionSet
    sub_isa: Optional[SubInstructionSet]
    bit_width: BitWidth
    endianness: Endianness
    processor: Optional[ProcessorType]
    mode: InstructionSetMode


LOGGER = logging.getLogger(__file__)


RE_REPRESENT_CONSTANTS_HEX = re.compile(r"(\W-?)([0-9]([^0-9x]|$))")
RE_RENAME_FP_TO_R11 = re.compile(r"(\W?)fp(\W?)")


class CapstoneDisassemblerService(DisassemblerServiceInterface):
    def __init__(self):
        self._cs_instance_by_attributes: Dict[CapstoneDisassemblerType, Cs] = dict()
        self._cs_instances_with_no_register_access = set()

    def _cs_disassemble(self, request: DisassemblerServiceRequest):
        cs_disassembler_type = _get_cs_disam_type(request)
        cs = self._get_cs(cs_disassembler_type)

        return cs.disasm(request.data, request.virtual_address)

    async def disassemble(self, request: DisassemblerServiceRequest) -> Iterable[DisassemblyResult]:
        res = []

        for cs_instruction in self._cs_disassemble(request):
            mnemonic, operands = _asm_fixups(
                cs_instruction.mnemonic, cs_instruction.op_str, request.isa
            )

            res.append(
                DisassemblyResult(
                    cs_instruction.address,
                    cs_instruction.size,
                    mnemonic,
                    operands,
                )
            )
        return res

    async def get_register_usage(self, request: DisassemblerServiceRequest) -> RegisterUsageResult:
        for cs_instruction in self._cs_disassemble(request):
            if request.isa is InstructionSet.X86 and cs_instruction.mnemonic == "cmp":
                raise DisassemblerRegisterUsageSupportError(
                    f"Capstone's support for x86 'cmp' instructions is flaky and platform "
                    f"dependent! For consistency, a hard error is always raised."
                )
            try:
                (regs_read_indexes, regs_write_indexes) = cs_instruction.regs_access()
            except CsError:
                raise DisassemblerRegisterUsageSupportError(
                    f"Capstone cannot get register usages for {_get_cs_disam_type(request)}"
                )
            regs_read = tuple(cs_instruction.reg_name(i) for i in regs_read_indexes)
            regs_written = tuple(cs_instruction.reg_name(i) for i in regs_write_indexes)

            return RegisterUsageResult(regs_read, regs_written)

        raise ValueError(
            "Capstone could not get register usage info because it could not find and "
            "instructions in the provided data!"
        )

    def _get_cs(self, cs_disam: CapstoneDisassemblerType):
        cs = self._cs_instance_by_attributes.get(cs_disam)
        if cs is None:
            cs = Cs(
                self._get_cs_arch_flag(cs_disam),
                self._get_cs_mode_flag(cs_disam),
            )
            cs.detail = True
            self._cs_instance_by_attributes[cs_disam] = cs

        return cs

    @staticmethod
    def _get_cs_arch_flag(cs_disam: CapstoneDisassemblerType):
        isa = cs_disam.isa
        bit_width = cs_disam.bit_width

        if isa is InstructionSet.ARM:
            return CS_ARCH_ARM64 if bit_width is BitWidth.BIT_64 else CS_ARCH_ARM
        elif isa is InstructionSet.X86:
            return CS_ARCH_X86
        elif isa is InstructionSet.PPC:
            return CS_ARCH_PPC
        elif isa is InstructionSet.MIPS:
            return CS_ARCH_MIPS
        elif isa is InstructionSet.AARCH64:
            return CS_ARCH_ARM64
        raise DisassemblerArchSupportError(
            f"Cannot generate the capstone architecture flag for {cs_disam}"
        )

    @staticmethod
    def _get_cs_mode_flag(cs_disam: CapstoneDisassemblerType):
        isa = cs_disam.isa
        bit_width = cs_disam.bit_width
        endianness = cs_disam.endianness
        processor = cs_disam.processor
        mode = cs_disam.mode

        if endianness is Endianness.BIG_ENDIAN:
            cs_endian_flag = CS_MODE_BIG_ENDIAN
        else:
            cs_endian_flag = CS_MODE_LITTLE_ENDIAN

        if isa is InstructionSet.AARCH64:
            mode_flag = 0
            return mode_flag | cs_endian_flag

        if isa is InstructionSet.ARM:
            mode_flag = 0
            if mode is InstructionSetMode.THUMB:
                # THUMB mode
                return mode_flag | CS_MODE_THUMB | cs_endian_flag
            elif bit_width is BitWidth.BIT_32:
                mode_flag |= CS_MODE_ARM
            if processor is None:
                # Plain ARM 32
                return mode_flag | cs_endian_flag
            if processor is ProcessorType.XSCALE:
                # XSCALE
                raise NotImplementedError("XSCALE not implemented")
            elif processor is ProcessorType.ARM926EJ_S:
                # ARMv5
                raise NotImplementedError("ARMv5E not implemented")
            else:
                # Default 32-bit ARM for other Processor types
                return mode_flag | cs_endian_flag

        elif isa is InstructionSet.X86:
            if bit_width is BitWidth.BIT_64:
                return CS_MODE_64 | cs_endian_flag
            elif bit_width is BitWidth.BIT_32:
                return CS_MODE_32 | cs_endian_flag
            elif bit_width is BitWidth.BIT_16:
                return CS_MODE_16 | cs_endian_flag

        elif isa is InstructionSet.PPC:
            if bit_width == BitWidth.BIT_64:
                return CS_MODE_64 | cs_endian_flag
            elif bit_width == BitWidth.BIT_32:
                return CS_MODE_32 | cs_endian_flag

        elif isa is InstructionSet.MIPS:
            if bit_width == BitWidth.BIT_64:
                return CS_MODE_64 | cs_endian_flag
            elif bit_width == BitWidth.BIT_32:
                return CS_MODE_32 | cs_endian_flag

        raise DisassemblerArchSupportError(f"Cannot generate the capstone mode flag for {cs_disam}")


def _asm_fixups(base_mnemonic: str, base_operands: str, isa: InstructionSet) -> Tuple[str, str]:
    operands = re.sub(RE_REPRESENT_CONSTANTS_HEX, r"\g<1>0x\g<2>", base_operands)
    if isa is InstructionSet.ARM:
        operands = re.sub(RE_RENAME_FP_TO_R11, r"\1r11\2", operands)

    mnemonic = base_mnemonic

    return mnemonic, operands


def _get_cs_disam_type(request: DisassemblerServiceRequest) -> CapstoneDisassemblerType:
    return CapstoneDisassemblerType(
        request.isa,
        request.sub_isa,
        request.bit_width,
        request.endianness,
        request.processor,
        request.mode,
    )
