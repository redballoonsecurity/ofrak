import pytest
from ofrak_type import ArchInfo
from ofrak_patch_maker.toolchain.gnu_avr import GNU_AVR_5_Toolchain
from .toolchain_under_test import ToolchainUnderTest
from .toolchain_asm import (
    run_monkey_patch_test,
)
from .toolchain_c import run_hello_world_test, run_bounds_check_test
from ofrak_type.architecture import (
    InstructionSet,
    ProcessorType,
    SubInstructionSet,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

AVR_EXTENSION = ".avr"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_AVR_5_Toolchain,
            ArchInfo(
                InstructionSet.AVR,
                SubInstructionSet.AVR2,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.AVR,
            ),
            AVR_EXTENSION,
        )
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# ASM Tests
def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    with pytest.raises(ValueError) as e_info:
        run_monkey_patch_test(toolchain_under_test)
    assert str(e_info.value) == "-pie not supported for AVR"


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(toolchain_under_test)
