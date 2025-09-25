from dataclasses import dataclass

from ofrak_type.architecture import InstructionSetMode
from ofrak.core.instruction import Instruction
from ofrak import OFRAKContext
from ..model import FlattenedResource


@dataclass
class InstructionModifierTestCase:
    label: str
    instruction_resource: FlattenedResource
    new_instruction_mnemonic: str
    new_instruction_operands: str
    new_instruction_mode: InstructionSetMode
    expected_data: bytes


async def run_instruction_modifier_test(
    ofrak_context: OFRAKContext, test_case: InstructionModifierTestCase
):
    new_r, _ = await test_case.instruction_resource.inflate(ofrak_context)
    instr = await new_r.view_as(Instruction)

    modified_machine_code = await instr.modify_assembly(
        test_case.new_instruction_mnemonic,
        test_case.new_instruction_operands,
        test_case.new_instruction_mode,
    )
    assert test_case.expected_data == modified_machine_code
