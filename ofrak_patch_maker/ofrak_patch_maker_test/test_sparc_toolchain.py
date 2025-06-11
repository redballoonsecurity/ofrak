import pytest
import platform

from ofrak_patch_maker.toolchain.gnu_bcc_sparc import GNU_BCC_SPARC_Toolchain
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_patch_maker_test.toolchain_asm import run_monkey_patch_test
from ofrak_patch_maker_test.toolchain_c import (
    run_bounds_check_test,
    run_hello_world_test,
    run_relocatable_test,
)
from ofrak_type import ArchInfo, InstructionSet, BitWidth, Endianness

SPARC_EXTENSION = ".sparc"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_BCC_SPARC_Toolchain,
            ArchInfo(
                InstructionSet.SPARC,
                None,
                BitWidth.BIT_32,
                Endianness.BIG_ENDIAN,
                None,
            ),
            SPARC_EXTENSION,
        ),
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


@pytest.mark.skipif(platform.machine() != "x86_64", reason="Test only supported on x86_64")
def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    run_monkey_patch_test(toolchain_under_test)


# C Tests
@pytest.mark.skipif(platform.machine() != "x86_64", reason="Test only supported on x86_64")
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test)


@pytest.mark.skipif(platform.machine() != "x86_64", reason="Test only supported on x86_64")
def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(toolchain_under_test)


@pytest.mark.skipif(platform.machine() != "x86_64", reason="Test only supported on x86_64")
def test_relocatable(toolchain_under_test: ToolchainUnderTest, tmp_path):
    run_relocatable_test(toolchain_under_test, tmp_path)
