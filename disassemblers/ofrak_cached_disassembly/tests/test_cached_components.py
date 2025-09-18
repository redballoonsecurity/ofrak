import os
from typing import Dict, Tuple
import pytest
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.filesystem import File
from ofrak.core.instruction import Instruction
from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_cached_disassembly.components.cached_disassembly import CachedAnalysisStore
from ofrak_cached_disassembly.components.cached_disassembly_unpacker import (
    CachedAnalysisAnalyzer,
    CachedAnalysisAnalyzerConfig,
    CachedProgramUnpacker,
)

from ofrak_type import InstructionSetMode, List
from pytest_ofrak.patterns.code_region_unpacker import (
    CodeRegionUnpackAndVerifyPattern,
    CodeRegionUnpackerTestCase,
)
from pytest_ofrak.patterns.complex_block_unpacker import (
    ComplexBlockUnpackerUnpackAndVerifyPattern,
    ComplexBlockUnpackerTestCase,
)
from pytest_ofrak import ASSETS_DIR
from pytest_ofrak.patterns.basic_block_unpacker import (
    BasicBlockUnpackerUnpackAndVerifyPattern,
    BasicBlockUnpackerTestCase,
)
from ofrak.core.decompilation import DecompilationAnalysis, DecompilationAnalyzer
from ofrak.core.code_region import CodeRegion

import ofrak_cached_disassembly
from pytest_ofrak import ASSETS_DIR as PYTEST_OFRAK_ASSETS_DIR

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))


@pytest.fixture(autouse=True)
def pyghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_cached_disassembly)


class TestGhidraCodeRegionUnpackAndVerify(CodeRegionUnpackAndVerifyPattern):
    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: CodeRegionUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(PYTEST_OFRAK_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        CACHE_FILENAME = os.path.join(
            os.path.join(PYTEST_OFRAK_ASSETS_DIR, "cache"), unpack_verify_test_case.binary_filename
        )
        await resource.run(
            CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=CACHE_FILENAME)
        )
        return resource


class TestCachedComplexBlockUnpackAndVerify(ComplexBlockUnpackerUnpackAndVerifyPattern):
    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ComplexBlockUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(PYTEST_OFRAK_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        CACHE_FILENAME = os.path.join(
            os.path.join(PYTEST_OFRAK_ASSETS_DIR, "cache"), unpack_verify_test_case.binary_filename
        )
        await resource.run(
            CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=CACHE_FILENAME)
        )
        return resource

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
    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: BasicBlockUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(PYTEST_OFRAK_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        CACHE_FILENAME = os.path.join(
            os.path.join(PYTEST_OFRAK_ASSETS_DIR, "cache"), unpack_verify_test_case.binary_filename
        )
        await resource.run(
            CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=CACHE_FILENAME)
        )
        return resource


INSTRUCTION_MODE_TEST_CASES = [
    ("fib", "fib.json", InstructionSetMode.NONE),
    ("fib_thumb", "fib_thumb.json", InstructionSetMode.THUMB),
]


@pytest.fixture(params=INSTRUCTION_MODE_TEST_CASES, ids=lambda tc: tc[0])
async def test_case(
    pyghidra_components: None, ofrak_context: OFRAKContext, request
) -> Tuple[Resource, InstructionSetMode]:
    binary_name, cache_name, mode = request.param
    binary_path = os.path.join(ASSETS_DIR, binary_name)
    resource = await ofrak_context.create_root_resource_from_file(binary_path)
    cache_path = os.path.join(ASSETS_DIR, cache_name)
    await resource.run(
        CachedAnalysisAnalyzer, config=CachedAnalysisAnalyzerConfig(filename=cache_path)
    )
    return resource, mode


async def test_instruction_mode(test_case: Tuple[Resource, InstructionSetMode]):
    """
    Test unpacking instructions with different instructions sets
    """
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
        os.path.join(ASSETS_DIR, "hello.x64.elf")
    )
    await root_resource.run(
        CachedAnalysisAnalyzer,
        config=CachedAnalysisAnalyzerConfig(
            filename=os.path.join(ASSETS_DIR, "hello.x64.elf.json")
        ),
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
        cached_resource: DecompilationAnalysis = await complex_block.resource.view_as(
            DecompilationAnalysis
        )
        decomps.append(cached_resource.decompilation)
    assert len(decomps) == 14
    assert "" not in decomps
    assert "main" in " ".join(decomps)
    assert "print" in " ".join(decomps)


def test_id_exists(ofrak_context: OFRAKContext):
    """
    Add a cached analysis to the store and check that the id exists within the store
    """
    cached_store = CachedAnalysisStore()
    cached_store.store_analysis(b"1234", {"test": "store"})
    assert cached_store.id_exists(b"1234"), "Resource id not found in CachedAnalysisStore"


async def test_cached_program_unpacker(pyghidra_components, ofrak_context: OFRAKContext):
    """
    Test that the CachedProgramUnpacker unpacks a resource into CodeRegions
    """
    root_resource = await ofrak_context.create_root_resource_from_file(
        os.path.join(ASSETS_DIR, "hello.x64.elf")
    )
    cached_analysis_view = await root_resource.run(
        CachedAnalysisAnalyzer,
        config=CachedAnalysisAnalyzerConfig(
            filename=os.path.join(ASSETS_DIR, "hello.x64.elf.json")
        ),
    )

    await root_resource.unpack_recursively()

    await root_resource.run(CachedProgramUnpacker)

    code_regions = await root_resource.get_descendants_as_view(
        CodeRegion, r_filter=ResourceFilter.with_tags(CodeRegion)
    )
    assert len(list(code_regions)) > 0, "No CodeRegions were created by CachedProgramUnpacker"


async def test_load_cached_analysis(ofrak_context: OFRAKContext):
    root_resource = await ofrak_context.create_root_resource_from_file(
        os.path.join(ASSETS_DIR, "hello.x64.elf")
    )
    await root_resource.run(
        CachedAnalysisAnalyzer,
        config=CachedAnalysisAnalyzerConfig(
            filename=os.path.join(ASSETS_DIR, "hello.x64.elf.json")
        ),
    )

    injector = ofrak_context.injector
    cached_store = await injector.get_instance(CachedAnalysisStore)
    analysis = cached_store.get_analysis(root_resource.get_id())

    assert analysis["metadata"]["decompiled"] == True
    assert analysis["func_4496"]["name"] == "_init"
    assert analysis["func_4496"]["decompilation"] != ""
