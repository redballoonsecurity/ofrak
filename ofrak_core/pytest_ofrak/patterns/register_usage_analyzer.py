from dataclasses import dataclass
from typing import Tuple

import pytest

from ofrak import OFRAKContext
from ofrak_type.architecture import InstructionSetMode
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.instruction import Instruction, RegisterUsage
from ofrak.service.assembler.assembler_service_i import AssemblerServiceInterface
from test_ofrak.constants import ARM32_ARCH, X64_ARCH, PPC_ARCH


@dataclass
class RegisterAnalyzerTestCase:
    program_attributes: ProgramAttributes
    instruction: Instruction
    expected_regs_read: Tuple[str, ...]
    expected_regs_written: Tuple[str, ...]

    @property
    def label(self):
        return f"{self.program_attributes.isa.name}: {self.instruction.disassembly}"


ARM_REGISTER_USAGE_TEST_CASES = [
    RegisterAnalyzerTestCase(
        ARM32_ARCH,
        Instruction(
            0x100,
            0x4,
            "push {r4, r5, r6, r7, r8, lr}",
            "push",
            "{r4, r5, r6, r7, r8, lr}",
            InstructionSetMode.NONE,
        ),
        ("sp", "r4", "r5", "r6", "r7", "r8", "lr"),
        ("sp",),
    ),
    RegisterAnalyzerTestCase(
        ARM32_ARCH,
        Instruction(
            0x104,
            0x4,
            "mov r4, #0x0",
            "mov",
            "r4, #0x0",
            InstructionSetMode.NONE,
        ),
        (),
        ("r4",),
    ),
    RegisterAnalyzerTestCase(
        ARM32_ARCH,
        Instruction(
            0x108,
            0x4,
            "mov r5, r4",
            "mov",
            "r5, r4",
            InstructionSetMode.NONE,
        ),
        ("r4",),
        ("r5",),
    ),
    RegisterAnalyzerTestCase(
        ARM32_ARCH,
        Instruction(
            0x10C,
            0x4,
            "ldr r6, [pc, #0x50]",
            "ldr",
            "r6, [pc, #0x50]",
            InstructionSetMode.NONE,
        ),
        ("pc",),
        ("r6",),
    ),
    RegisterAnalyzerTestCase(
        ARM32_ARCH,
        Instruction(
            0x110,
            0x4,
            "ldr r7, [pc, #0x50]",
            "ldr",
            "r7, [pc, #0x50]",
            InstructionSetMode.NONE,
        ),
        ("pc",),
        ("r7",),
    ),
]


X64_REGISTER_USAGE_TEST_CASES = [
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003E0,
            size=2,
            disassembly="xor ebp, ebp",
            mnemonic="xor",
            operands="ebp, ebp",
            mode=InstructionSetMode.NONE,
        ),
        ("ebp",),
        ("rflags", "ebp"),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003E2,
            size=3,
            disassembly="mov r9, rdx",
            mnemonic="mov",
            operands="r9, rdx",
            mode=InstructionSetMode.NONE,
        ),
        ("rdx",),
        ("r9",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003E5,
            size=1,
            disassembly="pop rsi",
            mnemonic="pop",
            operands="rsi",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rsp", "rsi"),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003E6,
            size=3,
            disassembly="mov rdx, rsp",
            mnemonic="mov",
            operands="rdx, rsp",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rdx",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003ED,
            size=1,
            disassembly="push rax",
            mnemonic="push",
            operands="rax",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp", "rax"),
        ("rsp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003EE,
            size=1,
            disassembly="push rsp",
            mnemonic="push",
            operands="rsp",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rsp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003EF,
            size=7,
            disassembly="mov r8, 0x4004e0",
            mnemonic="mov",
            operands="r8, 0x4004e0",
            mode=InstructionSetMode.NONE,
        ),
        (),
        ("r8",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003F6,
            size=7,
            disassembly="mov rcx, 0x4004f0",
            mnemonic="mov",
            operands="rcx, 0x4004f0",
            mode=InstructionSetMode.NONE,
        ),
        (),
        ("rcx",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x4003FD,
            size=7,
            disassembly="mov rdi, 0x4004c4",
            mnemonic="mov",
            operands="rdi, 0x4004c4",
            mode=InstructionSetMode.NONE,
        ),
        (),
        ("rdi",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400404,
            size=5,
            disassembly="call 0x4003c8",
            mnemonic="call",
            operands="0x4003c8",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp", "rip"),
        ("rsp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400409,
            size=1,
            disassembly="hlt ",
            mnemonic="hlt",
            operands="",
            mode=InstructionSetMode.NONE,
        ),
        (),
        (),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x40040C,
            size=4,
            disassembly="sub rsp, 0x8",
            mnemonic="sub",
            operands="rsp, 0x8",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rflags", "rsp"),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400410,
            size=7,
            disassembly="mov rax, qword ptr [0x600840]",
            mnemonic="mov",
            operands="rax, qword ptr [0x600840]",
            mode=InstructionSetMode.NONE,
        ),
        ("rip",),
        ("rax",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400417,
            size=3,
            disassembly="test rax, rax",
            mnemonic="test",
            operands="rax, rax",
            mode=InstructionSetMode.NONE,
        ),
        ("rax",),
        ("rflags",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x40041A,
            size=2,
            disassembly="jz 0x40041e",
            mnemonic="jz",
            operands="0x40041e",
            mode=InstructionSetMode.NONE,
        ),
        ("rflags",),
        (),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x40041E,
            size=4,
            disassembly="add rsp, 0x8",
            mnemonic="add",
            operands="rsp, 0x8",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rflags", "rsp"),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400422,
            size=1,
            disassembly="ret ",
            mnemonic="ret",
            operands="",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rsp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x40041C,
            size=2,
            disassembly="call rax",
            mnemonic="call",
            operands="rax",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp", "rax"),
        ("rsp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400430,
            size=1,
            disassembly="push rbp",
            mnemonic="push",
            operands="rbp",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp", "rbp"),
        ("rsp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400431,
            size=3,
            disassembly="mov rbp, rsp",
            mnemonic="mov",
            operands="rbp, rsp",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rbp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400434,
            size=1,
            disassembly="push rbx",
            mnemonic="push",
            operands="rbx",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp", "rbx"),
        ("rsp",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400435,
            size=4,
            disassembly="sub rsp, 0x8",
            mnemonic="sub",
            operands="rsp, 0x8",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rflags", "rsp"),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400439,
            size=7,
            disassembly="cmp byte ptr [0x600880], 0x0",
            mnemonic="cmp",
            operands="byte ptr [0x600880], 0x0",
            mode=InstructionSetMode.NONE,
        ),
        ("rip",),
        ("rflags",),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400491,
            size=1,
            disassembly="pop rbx",
            mnemonic="pop",
            operands="rbx",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rsp", "rbx"),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400492,
            size=1,
            disassembly="leave ",
            mnemonic="leave",
            operands="",
            mode=InstructionSetMode.NONE,
        ),
        ("rbp", "rsp"),
        ("rbp", "rsp"),
    ),
    RegisterAnalyzerTestCase(
        X64_ARCH,
        Instruction(
            virtual_address=0x400493,
            size=1,
            disassembly="ret ",
            mnemonic="ret",
            operands="",
            mode=InstructionSetMode.NONE,
        ),
        ("rsp",),
        ("rsp",),
    ),
]

PPC_REGISTER_USAGE_TEST_CASES = [
    RegisterAnalyzerTestCase(
        PPC_ARCH,
        Instruction(
            0x100,
            0x4,
            "add r4, r5, r6",
            "add",
            "r4, r5, r6",
            InstructionSetMode.NONE,
        ),
        ("r4", "r5", "r6"),
        ("r4",),
    ),
]


REGISTER_USAGE_TEST_CASES = (
    ARM_REGISTER_USAGE_TEST_CASES + X64_REGISTER_USAGE_TEST_CASES + PPC_REGISTER_USAGE_TEST_CASES
)


class RegisterUsageTestPattern:
    @pytest.fixture
    async def assembler_service(self, ofrak_context: OFRAKContext):
        return await ofrak_context.injector.get_instance(AssemblerServiceInterface)

    def case_is_known_broken(self, test_case: RegisterAnalyzerTestCase) -> Tuple[bool, str]:
        """
        Reimplement this method with a check to find test cases we know should break for an
        implementation.

        This method can return a string with the reason the test case is known to be broken. The
        returned string will be displayed as the reason the test was skipped.

        :return: A tuple of True or False for is or is not known broken, and a string with the
        reason the test case is broken.
        """
        return False, ""

    @pytest.mark.parametrize("test_case", REGISTER_USAGE_TEST_CASES, ids=lambda tc: tc.label)
    async def test_register_usage_analyzer(
        self, test_case: RegisterAnalyzerTestCase, ofrak_context, assembler_service
    ):
        test_case_is_broken, reason = self.case_is_known_broken(test_case)
        if test_case_is_broken:
            if not reason:
                reason = "test case is known to be broken"
            pytest.skip(reason)

        await self._get_and_check_register_usage(test_case, ofrak_context, assembler_service)

    @pytest.mark.parametrize("test_case", REGISTER_USAGE_TEST_CASES, ids=lambda tc: tc.label)
    async def test_known_broken_cases(
        self, test_case: RegisterAnalyzerTestCase, ofrak_context, assembler_service
    ):
        """
        Test that cases which are marked as known broken are still broken. If something has changed
        to make them no longer break as expected, the test must be updated.
        """
        test_case_is_broken, _ = self.case_is_known_broken(test_case)
        if not test_case_is_broken:
            pytest.skip("test case not broken")

        with pytest.raises(Exception):
            await self._get_and_check_register_usage(test_case, ofrak_context, assembler_service)

    async def _get_and_check_register_usage(
        self, test_case: RegisterAnalyzerTestCase, ofrak_context, assembler_service
    ):
        instr_data = await assembler_service.assemble(
            test_case.instruction.disassembly,
            test_case.instruction.virtual_address,
            test_case.program_attributes,
            test_case.instruction.mode,
        )
        instr_r = await ofrak_context.create_root_resource(
            "test_resource", instr_data, tags=(Instruction,)
        )
        instr_r.add_view(test_case.instruction)
        instr_r.add_attributes(test_case.program_attributes)
        await instr_r.save()

        register_usage = await instr_r.analyze(RegisterUsage)

        assert set(test_case.expected_regs_read) == set(
            register_usage.registers_read
        ), self._pretty_print_fail(test_case.expected_regs_read, register_usage.registers_read)
        assert set(test_case.expected_regs_written) == set(
            register_usage.registers_written
        ), self._pretty_print_fail(
            test_case.expected_regs_written, register_usage.registers_written
        )

    @staticmethod
    def _pretty_print_fail(expected, actual):
        return f"missing: {set(expected).difference(actual)}, unexpected: {set(actual).difference(expected)}"
