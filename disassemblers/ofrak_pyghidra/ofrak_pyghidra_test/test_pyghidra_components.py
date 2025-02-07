import os
from typing import Dict
from ofrak.ofrak_context import OFRAKContext
from ofrak_type import InstructionSetMode
import pytest
from ofrak.core import *
from pytest_ofrak.patterns.code_region_unpacker import CodeRegionUnpackAndVerifyPattern
from pytest_ofrak.patterns.complex_block_unpacker import (
    ComplexBlockUnpackerUnpackAndVerifyPattern,
    ComplexBlockUnpackerTestCase,
)
from ofrak.core.decompilation import DecompilationAnalysis
from pytest_ofrak.patterns.basic_block_unpacker import BasicBlockUnpackerUnpackAndVerifyPattern
import ofrak_pyghidra

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))


@pytest.fixture(autouse=True)
def pyghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_pyghidra)


class TestGhidraCodeRegionUnpackAndVerify(CodeRegionUnpackAndVerifyPattern):
    pass


class TestGhidraComplexBlockUnpackAndVerify(ComplexBlockUnpackerUnpackAndVerifyPattern):
    @pytest.fixture
    async def expected_results(self, unpack_verify_test_case: ComplexBlockUnpackerTestCase) -> Dict:
        if unpack_verify_test_case.binary_md5_digest == "fc7a6b95d993f955bd92f2bef2699dd0":
            return self._fixup_test_case_for_pie(
                unpack_verify_test_case.expected_results,
                pie_base_vaddr=0x10000,
            )

        return unpack_verify_test_case.expected_results

    @pytest.fixture
    async def optional_results(self, unpack_verify_test_case: ComplexBlockUnpackerTestCase):
        if unpack_verify_test_case.binary_md5_digest == "fc7a6b95d993f955bd92f2bef2699dd0":
            return set(
                self._fixup_test_case_for_pie(
                    {vaddr: [] for vaddr in unpack_verify_test_case.optional_results},
                    pie_base_vaddr=0x10000,
                ).keys()
            )

        return unpack_verify_test_case.optional_results


class TestGhidraBasicBlockUnpackAndVerify(BasicBlockUnpackerUnpackAndVerifyPattern):
    pass


INSTRUCTION_MODE_TEST_CASES = [
    ("fib", InstructionSetMode.NONE),
    ("fib_thumb", InstructionSetMode.THUMB),
]


@pytest.fixture(params=INSTRUCTION_MODE_TEST_CASES, ids=lambda tc: tc[0])
async def test_case(
    pyghidra_components: None, ofrak_context: OFRAKContext, request
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


async def test_cached_decompilation(ofrak_context: OFRAKContext):
    root_resource = await ofrak_context.create_root_resource_from_file(
        os.path.join(os.path.dirname(__file__), "assets/hello.x64.elf")
    )
    await root_resource.unpack_recursively(
        do_not_unpack=[
            ComplexBlock,
        ]
    )
    complex_blocks: List[ComplexBlock] = await root_resource.get_descendants_as_view(
        ComplexBlock,
        r_filter=ResourceFilter(
            tags=[
                ComplexBlock,
            ]
        ),
    )
    decomps = []
    for complex_block in complex_blocks:
        await complex_block.resource.identify()
        ghidra_resource: DecompilationAnalysis = await complex_block.resource.view_as(
            DecompilationAnalysis
        )
        decomps.append(ghidra_resource.decompilation)
    assert len(decomps) == 14
    assert "" not in decomps
    assert "main" in " ".join(decomps)
    assert "print" in " ".join(decomps)
