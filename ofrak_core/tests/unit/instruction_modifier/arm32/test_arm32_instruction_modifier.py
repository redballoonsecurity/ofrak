import pytest

from ofrak.model.viewable_tag_model import AttributesType
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.architecture import (
    InstructionSet,
    InstructionSetMode,
    ProcessorType,
)
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.instruction import Instruction
from ..instruction_modifier_test import (
    InstructionModifierTestCase,
    run_instruction_modifier_test,
)
from ...model import FlattenedResource

ARM32_INSTRUCTION_MODIFICATION_TEST_CASES = [
    InstructionModifierTestCase(
        "Non-thumb mnemonic change",
        # From LDRSH.W         R3, [R7,#0x14+var_8]
        # To   LDRH            R3, [R7,#0x14+var_8]
        FlattenedResource(
            (Instruction,),
            (
                AttributesType[Instruction](
                    "ldrsh.w",
                    "r3, [r7,#0x1C]",
                    InstructionSetMode.NONE,
                ),
                ProgramAttributes(
                    isa=InstructionSet.ARM,
                    sub_isa=None,
                    bit_width=BitWidth.BIT_32,
                    endianness=Endianness.LITTLE_ENDIAN,
                    processor=ProcessorType.GENERIC_A9_V7,
                ),
            ),
            (),
            data=b"\xfc\x31\xd7\xe1",
            vaddr_and_size=(0x1_000_000, 0x4),
        ),
        "ldrh",
        "r3, [r7,#0x1C]",
        InstructionSetMode.NONE,
        b"\xbc\x31\xd7\xe1",
    ),
    InstructionModifierTestCase(
        "Thumb mnemonic change",
        # From ADD R2, R3, 1
        # To   SUB R2, R3, 1
        FlattenedResource(
            (Instruction,),
            (
                AttributesType[Instruction](
                    "add",
                    "r2, r3, 1",
                    InstructionSetMode.THUMB,
                ),
                ProgramAttributes(
                    isa=InstructionSet.ARM,
                    sub_isa=None,
                    bit_width=BitWidth.BIT_32,
                    endianness=Endianness.LITTLE_ENDIAN,
                    processor=ProcessorType.GENERIC_A9_V7,
                ),
            ),
            (),
            data=b"\x03\xf1\x01\x02",
            vaddr_and_size=(0x1_000_000, 0x4),
        ),
        "sub",
        "r2, r3, 1",
        InstructionSetMode.THUMB,
        b"\xa3\xf1\x01\x02",
    ),
    InstructionModifierTestCase(
        "Non-thumb to Thumb mnemonic change",
        # From ADD R2, R3, 1
        # To   SUB R2, R3, 1
        FlattenedResource(
            (Instruction,),
            (
                AttributesType[Instruction](
                    "add",
                    "r2, r3, 1",
                    InstructionSetMode.NONE,
                ),
                ProgramAttributes(
                    isa=InstructionSet.ARM,
                    sub_isa=None,
                    bit_width=BitWidth.BIT_32,
                    endianness=Endianness.LITTLE_ENDIAN,
                    processor=ProcessorType.GENERIC_A9_V7,
                ),
            ),
            (),
            data=b"\x01\x20\x83\xe2",
            vaddr_and_size=(0x1_000_000, 0x4),
        ),
        "sub",
        "r2, r3, 1",
        InstructionSetMode.THUMB,
        b"\xa3\xf1\x01\x02",
    ),
]


@pytest.mark.parametrize(
    "test_case", ARM32_INSTRUCTION_MODIFICATION_TEST_CASES, ids=lambda tc: tc.label
)
async def test_arm32_instruction_modifier(ofrak_context, test_case):
    await run_instruction_modifier_test(ofrak_context, test_case)
