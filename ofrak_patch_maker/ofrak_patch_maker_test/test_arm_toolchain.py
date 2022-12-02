import pytest

from ofrak.core.architecture import ProgramAttributes
from ofrak_patch_maker.toolchain.version import ToolchainVersion
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_patch_maker_test.toolchain_asm import (
    run_challenge_3_reloc_toy_example_test,
    run_monkey_patch_test,
)
from ofrak_patch_maker_test.toolchain_c import run_hello_world_test, run_bounds_check_test
from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    ProcessorType,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

ARM_EXTENSION = ".arm"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            ToolchainVersion.GNU_ARM_NONE_EABI_10_2_1,
            ProgramAttributes(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
        ),
        ToolchainUnderTest(
            ToolchainVersion.LLVM_12_0_1,
            ProgramAttributes(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
        ),
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# ASM Tests
def test_challenge_3_reloc_toy_example(toolchain_under_test: ToolchainUnderTest):
    run_challenge_3_reloc_toy_example_test(
        toolchain_under_test.toolchain_version,
        toolchain_under_test.proc,
        toolchain_under_test.extension,
    )


def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    run_monkey_patch_test(
        toolchain_under_test.toolchain_version,
        toolchain_under_test.proc,
        toolchain_under_test.extension,
    )


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test.toolchain_version, toolchain_under_test.proc)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(
        toolchain_under_test.toolchain_version,
        toolchain_under_test.proc,
    )
