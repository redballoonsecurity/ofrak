from ofrak.core.instruction import Instruction
import os
from typing import Dict, Tuple
from ofrak.core.complex_block import ComplexBlock
from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type import BitWidth, InstructionSetMode, List, ProcessorType, SubInstructionSet
import pytest
from pytest_ofrak.patterns.code_region_unpacker import CodeRegionUnpackAndVerifyPattern
from pytest_ofrak.patterns.complex_block_unpacker import (
    ComplexBlockUnpackerUnpackAndVerifyPattern,
    ComplexBlockUnpackerTestCase,
)
from ofrak.core.decompilation import DecompilationAnalysis, DecompilationAnalyzer
from pytest_ofrak.patterns.basic_block_unpacker import BasicBlockUnpackerUnpackAndVerifyPattern
from ofrak_pyghidra.components.pyghidra_components import _arch_info_to_processor_id
from ofrak_type import ArchInfo, Endianness, InstructionSet
import ofrak_pyghidra
from ofrak.core.code_region import CodeRegion
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort
from ofrak_pyghidra.standalone.pyghidra_analysis import unpack, decompile_all_functions

ASSETS_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../ofrak_cached_disassembly/tests/assets",
    )
)


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


ARCH_INFO_TEST_CASES = [
    (
        ArchInfo(
            isa=InstructionSet.ARM,
            endianness=Endianness.LITTLE_ENDIAN,
            bit_width=BitWidth.BIT_32,
            processor=ProcessorType.ARM926EJ_S,
            sub_isa=SubInstructionSet.ARMv9A,
        ),
        "ARM:LE:32:v8",
    ),
    (
        ArchInfo(
            isa=InstructionSet.X86,
            endianness=Endianness.LITTLE_ENDIAN,
            bit_width=BitWidth.BIT_64,
            processor=ProcessorType.X64,
            sub_isa=None,
        ),
        "x86:LE:64:default",
    ),
]


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


async def test_decompilation(ofrak_context: OFRAKContext):
    root_resource = await ofrak_context.create_root_resource_from_file(
        os.path.join(ASSETS_DIR, "hello.x64.elf")
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
        await complex_block.resource.run(DecompilationAnalyzer)
        pyghidra_resource: DecompilationAnalysis = await complex_block.resource.view_as(
            DecompilationAnalysis
        )
        decomps.append(pyghidra_resource.decompilation)
    assert len(decomps) == 14
    assert "" not in decomps
    assert "main" in " ".join(decomps)
    assert "print" in " ".join(decomps)


async def test_pyghidra_standalone_unpack_decompiled():
    program_file = os.path.join(ASSETS_DIR, "hello.x64.elf")
    decompiled = True
    unpack_results = unpack(program_file, decompiled, language=None)
    assert "metadata" in unpack_results
    assert "path" in unpack_results["metadata"]
    assert unpack_results["metadata"]["path"] == program_file
    main_cb_key = f"func_{0x12c7}"
    assert main_cb_key in unpack_results, list(
        filter(lambda k: k.startswith("func_"), unpack_results.keys())
    )
    assert "decompilation" in unpack_results[main_cb_key]
    assert "main" in unpack_results[main_cb_key]["decompilation"]
    assert "printf" in unpack_results[main_cb_key]["decompilation"]


async def test_pyghidra_standalone_decompile_all_functions():
    program_file = os.path.join(ASSETS_DIR, "hello.x64.elf")
    decompilation_results = decompile_all_functions(program_file, language=None)
    main_cb_key = f"func_{0x12c7}"
    assert main_cb_key in decompilation_results
    assert "main" in decompilation_results[main_cb_key]
    assert "printf" in decompilation_results[main_cb_key]


@pytest.mark.parametrize("arch, expected_processor_id", ARCH_INFO_TEST_CASES)
def test_arch_info_to_processor_id(arch, expected_processor_id):
    assert _arch_info_to_processor_id(arch) == expected_processor_id


@pytest.fixture
async def program_resource(ofrak_context: OFRAKContext):
    # program compiled from examples/src
    return await ofrak_context.create_root_resource_from_file(
        os.path.join(os.path.dirname(__file__), "assets/program")
    )


async def test_PIE_code_regions(program_resource, ofrak_injector):
    """
    PIE binaries are loaded at address 0x100000 in Ghidra. Verify that unpacking CodeRegions creates them at the right virtual addresses.
    """
    await program_resource.unpack()
    code_regions = await program_resource.get_descendants_as_view(
        v_type=CodeRegion, r_filter=ResourceFilter(tags=[CodeRegion])
    )
    for cr in code_regions:
        await cr.resource.unpack()

    code_regions = await program_resource.get_descendants_as_view(
        v_type=CodeRegion,
        r_filter=ResourceFilter(tags=[CodeRegion]),
        r_sort=ResourceSort(CodeRegion.VirtualAddress),
    )
    assert len(code_regions) == 5
    assert code_regions[0].virtual_address == 0x101000 and code_regions[0].size == 0x17
    assert code_regions[1].virtual_address == 0x101020 and code_regions[1].size == 0x20
    assert code_regions[2].virtual_address == 0x101040 and code_regions[2].size == 0x8
    assert code_regions[3].virtual_address == 0x101050 and code_regions[3].size == 0x103
    assert code_regions[4].virtual_address == 0x101154 and code_regions[4].size == 0x9
