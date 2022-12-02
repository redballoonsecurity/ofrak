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
    ProcessorType,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

M68K_EXTENSION = ".m68k"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            ToolchainVersion.GNU_M68K_LINUX_10,
            ProgramAttributes(
                InstructionSet.M68K,
                None,
                BitWidth.BIT_32,
                Endianness.BIG_ENDIAN,
                ProcessorType.COLDFIRE4E,
            ),
            M68K_EXTENSION,
        ),
        ToolchainUnderTest(
            ToolchainVersion.VBCC_M68K_0_9,
            ProgramAttributes(
                InstructionSet.M68K,
                None,
                BitWidth.BIT_32,
                Endianness.BIG_ENDIAN,
                ProcessorType.COLDFIRE4E,
            ),
            M68K_EXTENSION,
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
