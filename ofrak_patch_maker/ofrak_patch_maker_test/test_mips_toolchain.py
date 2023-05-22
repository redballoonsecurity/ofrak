import pytest

from ofrak_patch_maker.toolchain.gnu_mips import GNU_MIPS_LINUX_10_Toolchain
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_patch_maker_test.toolchain_asm import (
    run_monkey_patch_test,
)
from ofrak_patch_maker_test.toolchain_c import (
    run_bounds_check_test,
    run_hello_world_test,
)
from ofrak_type import ArchInfo, InstructionSet, BitWidth, Endianness

MIPS_EXTENSION = ".mips"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_MIPS_LINUX_10_Toolchain,
            ArchInfo(
                InstructionSet.MIPS,
                None,
                BitWidth.BIT_32,
                Endianness.BIG_ENDIAN,
                None,
            ),
            MIPS_EXTENSION,
        ),
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# ASM Tests
# def test_challenge_3_reloc_toy_example(toolchain_under_test: ToolchainUnderTest):
#     # TODO
#     pass


def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    run_monkey_patch_test(toolchain_under_test)


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(toolchain_under_test)
