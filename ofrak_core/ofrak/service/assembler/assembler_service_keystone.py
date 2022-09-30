import sys
from typing import AsyncIterator, Iterable

from keystone import (
    KS_ARCH_ARM64,
    KS_ARCH_ARM,
    KS_ARCH_X86,
    KS_MODE_THUMB,
    KS_MODE_ARM,
    KS_MODE_64,
    KS_MODE_32,
    KS_MODE_16,
    Ks,
    KsError,
    KS_ARCH_PPC,
    KS_MODE_BIG_ENDIAN,
    KS_MODE_LITTLE_ENDIAN,
)

from ofrak.core.architecture import ProgramAttributes
from ofrak.service.assembler.assembler_service_i import AssemblerServiceInterface
from ofrak_io.stream_capture import StreamCapture
from ofrak_type.architecture import InstructionSet, InstructionSetMode, ProcessorType
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

X86_64_SPECIAL_CASES = {
    "mov rax, qword ptr fs:[0x28]": b"\x64\x48\x8B\x04\x25\x28\x00\x00\x00",
    "xor rdi, qword ptr fs:[0x28]": b"\x64\x48\x33\x3C\x25\x28\x00\x00\x00",
    "mov rcx, qword ptr fs:[0x28]": b"\x64\x48\x8B\x0C\x25\x28\x00\x00\x00",
    "xor rbx, qword ptr fs:[0x28]": b"\x64\x48\x33\x1C\x25\x28\x00\x00\x00",
    "xor rsi, qword ptr fs:[0x28]": b"\x64\x48\x33\x34\x25\x28\x00\x00\x00",
    "xor rdx, qword ptr fs:[0x28]": b"\x64\x48\x33\x14\x25\x28\x00\x00\x00",
    "xor rcx, qword ptr fs:[0x28]": b"\x64\x48\x33\x0C\x25\x28\x00\x00\x00",
    "xor rax, qword ptr fs:[0x28]": b"\x64\x48\x33\x04\x25\x28\x00\x00\x00",
}


class KeystoneAssemblerService(AssemblerServiceInterface):
    """
    An assembler service implementation using the keystone engine.
    """

    def __init__(self):
        self._ks_by_processor = {}

    @staticmethod
    def _get_keystone_arch_flag(
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode,
    ):
        if program_attributes.isa is InstructionSet.ARM:
            return KS_ARCH_ARM
        elif program_attributes.isa is InstructionSet.AARCH64:
            return KS_ARCH_ARM64
        elif program_attributes.isa is InstructionSet.X86:
            return KS_ARCH_X86
        elif program_attributes.isa is InstructionSet.PPC:
            return KS_ARCH_PPC
        raise ValueError(f"Cannot generate the keystone architecture flag for {program_attributes}")

    @staticmethod
    def _get_keystone_mode_flag(
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode,
    ):
        if program_attributes.endianness is Endianness.BIG_ENDIAN:
            ks_endian_flag = KS_MODE_BIG_ENDIAN
        else:
            ks_endian_flag = KS_MODE_LITTLE_ENDIAN

        if program_attributes.isa is InstructionSet.AARCH64:
            return ks_endian_flag

        elif program_attributes.isa is InstructionSet.ARM:
            mode_flag = 0
            if mode is InstructionSetMode.THUMB:
                # THUMB mode
                return mode_flag | KS_MODE_THUMB | ks_endian_flag
            elif program_attributes.bit_width is BitWidth.BIT_32:
                mode_flag |= KS_MODE_ARM
            if program_attributes.processor is None:
                # Plain ARM 32
                return mode_flag | ks_endian_flag
            if program_attributes.processor is ProcessorType.XSCALE:
                # XSCALE
                raise NotImplementedError("XSCALE not implemented")
            elif program_attributes.processor is ProcessorType.ARM926EJ_S:
                # ARMv5
                raise NotImplementedError("AMRv5 not implemented")
            else:
                # Default 32-bit ARM for other Processor types
                return mode_flag | ks_endian_flag

        elif program_attributes.isa is InstructionSet.X86:
            if program_attributes.bit_width is BitWidth.BIT_64:
                return KS_MODE_64 | ks_endian_flag
            elif program_attributes.bit_width is BitWidth.BIT_32:
                return KS_MODE_32 | ks_endian_flag
            elif program_attributes.bit_width is BitWidth.BIT_16:
                return KS_MODE_16 | ks_endian_flag

        elif program_attributes.isa is InstructionSet.PPC:
            if program_attributes.bit_width == BitWidth.BIT_64:
                return KS_MODE_64 | ks_endian_flag
            elif program_attributes.bit_width == BitWidth.BIT_32:
                return KS_MODE_32 | ks_endian_flag

        raise ValueError(f"Cannot generate the keystone mode flag for {program_attributes}")

    def _get_keystone_instance(
        self,
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> Ks:
        """
        Get or build a Keystone instance for the provided processor
        :param program_attributes:
        :param mode:
        """
        ks = self._ks_by_processor.get((program_attributes, mode), None)
        if ks is None:
            ks = Ks(
                self._get_keystone_arch_flag(program_attributes, mode),
                self._get_keystone_mode_flag(program_attributes, mode),
            )
            self._ks_by_processor[(program_attributes, mode)] = ks
        return ks

    async def assemble(
        self,
        assembly: str,
        vm_addr: int,
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> bytes:
        """
        Assemble the given assembly code using keystone.

        :param assembly:
        :param vm_addr:
        :param program_attributes:
        :param mode:

        :return: machine code
        """
        # TODO: This is a very temporary fix to T395.
        # TODO: Figure out where to actaully handle situations like this
        assembly_parts = None
        bad_instruction = None
        for instruction in X86_64_SPECIAL_CASES.keys():
            if instruction in assembly:
                assembly_parts = assembly.split(instruction)
                bad_instruction = instruction
                break
        if assembly_parts is not None and bad_instruction is not None:
            machine_code_parts = []
            assembly_size = 0
            for assembly_part in assembly_parts:
                if assembly_part == "":
                    machine_code_parts.append(b"")
                else:
                    machine_code_part = await self.assemble(
                        assembly_part, vm_addr + assembly_size, program_attributes
                    )
                    machine_code_parts.append(machine_code_part)
                    assembly_size += len(machine_code_part)
                assembly_size += 9
            machine_code = X86_64_SPECIAL_CASES[bad_instruction].join(machine_code_parts)
            if machine_code == "":
                return bytes(X86_64_SPECIAL_CASES[bad_instruction])
            return machine_code

        # special register prefix preprocessing for PPC
        preprocessed_assembly = assembly
        if program_attributes.isa is InstructionSet.PPC:
            for prefix in ["r", "f", "v"]:
                for n in range(32):
                    register_operand = f"{prefix}{n}"
                    preprocessed_assembly = preprocessed_assembly.replace(
                        r" %s," % register_operand, " %u," % n
                    )
                    preprocessed_assembly = preprocessed_assembly.replace(
                        r"(%s)" % register_operand, "(%u)" % n
                    )
                    preprocessed_assembly = preprocessed_assembly.replace(
                        r" %s" % register_operand, " %u" % n
                    )

        try:
            ks = self._get_keystone_instance(program_attributes, mode)
            if program_attributes.isa in (InstructionSet.ARM, InstructionSet.AARCH64):
                # This place is a message... and part of a system of messages ...pay attention to it!
                # Sending this message was important to us. We considered ourselves to be a powerful culture.
                # This place is not a place of honor ... no highly esteemed deed is commemorated here... nothing valued is here.
                # What is here was dangerous and repulsive to us. This message is a warning about danger.
                # The danger is in a particular location... it increases towards a center... the center of danger is here... of a particular size and shape, and below us.
                # The danger is still present, in your time, as it was in ours.
                # The danger is to the body, and it can kill.
                # The form of the danger is an emanation of energy.
                # The danger is unleashed only if you substantially disturb this place. This place is best shunned and left uninhabited.
                # Check for warnings in Keystone standard error.
                # If they appear, reset the Ks objects, as bugs in Keystone error handling
                # sometimes cause segmentation faults at subsequent calls to ks.asm.
                # See T403.
                with StreamCapture(sys.stderr) as stream_capture:
                    machine_code, _ = ks.asm(preprocessed_assembly, addr=vm_addr, as_bytes=True)
                if "warning:" in stream_capture.get_captured_stream():
                    self._ks_by_processor = {}
            else:
                machine_code, _ = ks.asm(preprocessed_assembly, addr=vm_addr, as_bytes=True)
            return machine_code
        except KsError as error:

            assembly_vm_addr = vm_addr
            failing_instruction = None

            for assembly_line in preprocessed_assembly.splitlines():
                try:
                    ks = self._get_keystone_instance(program_attributes, mode)
                    machine_code, _ = ks.asm(assembly_line, addr=assembly_vm_addr, as_bytes=True)
                    assembly_vm_addr += len(machine_code)

                except KsError:
                    failing_instruction = assembly_line
                    break

            raise Exception(
                "Keystone ERROR in {}:\n[0x{:x}]\n{}\nerror on instruction '{}' @ 0x{:x}: {}".format(
                    program_attributes.isa,
                    vm_addr,
                    preprocessed_assembly,
                    failing_instruction,
                    assembly_vm_addr,
                    error,
                )
            )

    async def assemble_many(
        self,
        assembly_list: Iterable[str],
        vm_addrs: Iterable[int],
        program_attributes: ProgramAttributes,
        mode=InstructionSetMode.NONE,  # type: InstructionSetMode
    ) -> AsyncIterator[bytes]:
        for assembly, vm_addr in zip(assembly_list, vm_addrs):
            result = await self.assemble(assembly, vm_addr, program_attributes, mode)
            yield result

    async def assemble_file(
        self,
        assembly_file: str,
        vm_addr: int,
        program_attributes: ProgramAttributes,
        mode=InstructionSetMode.NONE,
    ) -> bytes:
        """
        Assemble the given assembly file.

        :param assembly_file: The path to the assembly file.
        :param vm_addr: The virtual address at which the assembly file should be assembled.
        :param program_attributes: The processor targeted by the assembly
        :param mode: The mode of the processor for the assembly

        :return: The assembled machine code
        """
        with open(assembly_file) as file_handle:
            assembly = file_handle.read()
        # Keystone Seg faults when trying to assemble '.text'.
        # It is therefore stripped from the assembly here.
        assembly = assembly.replace(".text\n", "")
        return await self.assemble(assembly, vm_addr, program_attributes, mode)

    async def assemble_files(
        self,
        assembly_files: Iterable[str],
        vm_addrs: Iterable[int],
        program_attributes: ProgramAttributes,
        mode: InstructionSetMode = InstructionSetMode.NONE,
    ) -> AsyncIterator[bytes]:
        for assembly_file, vm_addr in zip(assembly_files, vm_addrs):
            yield await self.assemble_file(assembly_file, vm_addr, program_attributes, mode)
