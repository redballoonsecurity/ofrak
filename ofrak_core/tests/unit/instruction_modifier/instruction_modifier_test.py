"""
This module tests the instruction modifier functionality.

This module contains tests for modifying assembly instructions in binary resources,
verifying that the modification process correctly updates machine code according to
the specified mnemonic, operands, and instruction set mode.
"""

from dataclasses import dataclass

from ofrak_type.architecture import InstructionSetMode
from ofrak.core.instruction import Instruction
from ofrak import OFRAKContext
from ..model import FlattenedResource


@dataclass
class InstructionModifierTestCase:
    """
    A test case for instruction modification.

    This class represents a single test case for the instruction modifier functionality,
    containing all necessary information to perform an instruction modification test.
    - Contains the label for the test case
    - Holds the instruction resource to be modified
    - Specifies the new instruction mnemonic, operands, and mode
    - Defines the expected resulting machine code
    """

    label: str
    instruction_resource: FlattenedResource
    new_instruction_mnemonic: str
    new_instruction_operands: str
    new_instruction_mode: InstructionSetMode
    expected_data: bytes


async def run_instruction_modifier_test(
    ofrak_context: OFRAKContext, test_case: InstructionModifierTestCase
):
    """
    Execute a single instruction modifier test case.

    This function runs a complete test case for instruction modification by:
    - Creating a new resource from the test case's instruction resource
    - Viewing the resource as an Instruction
    - Modifying the assembly with the specified parameters
    - Asserting that the result matches the expected data
    """
    new_r, _ = await test_case.instruction_resource.inflate(ofrak_context)
    instr = await new_r.view_as(Instruction)

    modified_machine_code = await instr.modify_assembly(
        test_case.new_instruction_mnemonic,
        test_case.new_instruction_operands,
        test_case.new_instruction_mode,
    )
    assert test_case.expected_data == modified_machine_code
