import pytest

from ofrak.core.architecture import ProgramAttributes
from ofrak_patch_maker.toolchain.version import ToolchainVersion
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_patch_maker_test.toolchain_asm import (
    run_monkey_patch_test,
)
from ofrak_patch_maker_test.toolchain_c import run_hello_world_test, run_bounds_check_test
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
            ToolchainVersion.GNU_AVR_5,
            ProgramAttributes(
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
        run_monkey_patch_test(
            toolchain_under_test.toolchain_version,
            toolchain_under_test.proc,
            toolchain_under_test.extension,
        )
    assert str(e_info.value) == "-pie not supported for AVR"


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test.toolchain_version, toolchain_under_test.proc)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(
        toolchain_under_test.toolchain_version,
        toolchain_under_test.proc,
    )
