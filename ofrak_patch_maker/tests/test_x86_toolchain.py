import pytest

from ofrak_type import ArchInfo

from ofrak_patch_maker.toolchain.gnu_x86 import GNU_X86_32_LINUX_EABI_10_3_0_Toolchain
from ofrak_patch_maker.toolchain.gnu_x64 import GNU_X86_64_LINUX_EABI_10_3_0_Toolchain
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_patch_maker_test.toolchain_c import (
    run_hello_world_test,
    run_bounds_check_test,
    run_relocatable_test,
)
from ofrak_type.architecture import (
    InstructionSet,
    ProcessorType,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

X86_EXTENSION = ".x86"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_X86_64_LINUX_EABI_10_3_0_Toolchain,
            ArchInfo(
                InstructionSet.X86,
                None,
                BitWidth.BIT_64,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.X64,
            ),
            X86_EXTENSION,
        ),
        ToolchainUnderTest(
            GNU_X86_32_LINUX_EABI_10_3_0_Toolchain,
            ArchInfo(
                InstructionSet.X86,
                None,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.I386,
            ),
            X86_EXTENSION,
        ),
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(toolchain_under_test)


def test_relocatable(toolchain_under_test: ToolchainUnderTest, tmp_path):
    run_relocatable_test(toolchain_under_test, tmp_path)
