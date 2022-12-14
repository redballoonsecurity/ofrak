import os
from typing import Tuple

import pytest

from ofrak import OFRAKContext
from ofrak_type.architecture import InstructionSetMode
from ofrak.core.instruction import Instruction
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from pytest_ofrak.patterns.basic_block_unpacker import (
    BasicBlockUnpackerUnpackAndVerifyPattern,
)
from pytest_ofrak.patterns.code_region_unpacker import (
    CodeRegionUnpackAndVerifyPattern,
)
from pytest_ofrak.patterns.complex_block_unpacker import (
    ComplexBlockUnpackerUnpackAndVerifyPattern,
)

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))


class TestGhidraCodeRegionUnpackAndVerify(CodeRegionUnpackAndVerifyPattern):
    pass


class TestGhidraComplexBlockUnpackAndVerify(ComplexBlockUnpackerUnpackAndVerifyPattern):
    pass


class TestGhidraBasicBlockUnpackAndVerify(BasicBlockUnpackerUnpackAndVerifyPattern):
    pass


INSTRUCTION_MODE_TEST_CASES = [
    ("fib", InstructionSetMode.NONE),
    ("fib_thumb", InstructionSetMode.THUMB),
]


@pytest.fixture(params=INSTRUCTION_MODE_TEST_CASES, ids=lambda tc: tc[0])
async def test_case(
    ghidra_components: None, ofrak_context: OFRAKContext, request
) -> Tuple[Resource, InstructionSetMode]:
    binary_name, mode = request.param
    binary_path = os.path.join(ASSETS_DIR, binary_name)
    resource = await ofrak_context.create_root_resource_from_file(binary_path)
    return resource, mode


async def test_instruction_mode(test_case: Tuple[Resource, InstructionSetMode]):
    root_resource, mode = test_case
    await root_resource.unpack_recursively()
    instructions = list(
        await root_resource.get_descendants_as_view(
            Instruction, r_filter=ResourceFilter.with_tags(Instruction)
        )
    )
    # Using "any" instead of "all" because not 100% of the basic blocks in a binary compiled with
    # "-mthumb" are in THUMB mode. This is testing (de)serialization of Ghidra analysis,
    # so all that matters is that we're seeing some instructions of the expected type
    assert any(instruction.mode == mode for instruction in instructions), (
        f"None of the instructions in {root_resource.get_id().hex()} had the expected instruction "
        f"set mode of {mode.name}."
    )
