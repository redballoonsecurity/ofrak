"""
This module tests the PyGhidra component, including unpackers, disassembly and decompilation components.

Requirements Mapping:
- REQ1.2
- REQ2.2
"""
import os
from typing import Dict, Tuple
from ofrak.ofrak_context import OFRAKContext
from ofrak_type import (
    BitWidth,
    InstructionSetMode,
    List,
    ProcessorType,
    SubInstructionSet,
    Range,
    Endianness,
    ArchInfo,
    InstructionSet,
)
import pytest
from pytest_ofrak.patterns.code_region_unpacker import CodeRegionUnpackAndVerifyPattern
from pytest_ofrak.patterns.complex_block_unpacker import (
    ComplexBlockUnpackerUnpackAndVerifyPattern,
    ComplexBlockUnpackerTestCase,
)
from ofrak.core.decompilation import DecompilationAnalysis
from pytest_ofrak.patterns.basic_block_unpacker import BasicBlockUnpackerUnpackAndVerifyPattern
from ofrak_pyghidra.components.pyghidra_components import (
    _arch_info_to_processor_id,
    PyGhidraDecompilationAnalyzer,
    PyGhidraCustomLoadAnalyzer,
    PyGhidraCustomLoadProject,
)
import ofrak_pyghidra
from ofrak.core import (
    CodeRegion,
    MemoryRegion,
    Program,
    ComplexBlock,
    Addressable,
    Instruction,
    ProgramAttributes,
)
from pytest_ofrak.patterns.program_metadata import (
    custom_binary_resource,  # noqa: F401
    setup_program_with_code_region,
    add_rodata_region,
    assert_complex_block_at_vaddr,
)
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_pyghidra.standalone.pyghidra_analysis import unpack, decompile_all_functions
from ofrak import Resource, ResourceFilter, ResourceSort, ResourceAttributeValueFilter

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
    """
    Test code region unpacking with Ghidra backend (REQ1.2).

    This test verifies that:
    - Code regions can be successfully unpacked
    - The unpacking process works correctly with the Ghidra backend

    See `CodeRegionUnpackAndVerifyPattern` for more details on test cases.
    """


class TestGhidraComplexBlockUnpackAndVerify(ComplexBlockUnpackerUnpackAndVerifyPattern):
    """
    Test complex block unpacking functionality.

    This test verifies that:
    - Complex blocks are properly unpacked from binaries
    - PIE binary adjustments are handled properly
    """

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
    """
    Test unpacking instructions with different instruction set modes.

    This test verifies that:
    - Instructions can be unpacked using different instruction set modes
    - At least one instruction in the unpacked resource matches the expected mode
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


async def test_decompilation(ofrak_context: OFRAKContext):
    """
    Test decompilation analysis functionality.

    This test verifies that:
    - The decompilation analyzer correctly processes the test binary
    - A certain number of decompilation outputs are generated
    - The decompilation results contain expected keywords like 'main' and 'print'
    """
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
        await complex_block.resource.run(PyGhidraDecompilationAnalyzer)
        pyghidra_resource: DecompilationAnalysis = await complex_block.resource.view_as(
            DecompilationAnalysis
        )
        decomps.append(pyghidra_resource.decompilation)
    assert len(decomps) == 14
    assert "" not in decomps
    assert "main" in " ".join(decomps)
    assert "print" in " ".join(decomps)


async def test_pyghidra_standalone_unpack_decompiled():
    """
    Test standalone unpack function with decompilation.

    This test verifies that:
    - Unpack function correctly handles decompilation flag
    - Metadata is properly generated
    - Decompile output contains expected function content
    """
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
    """
    Test standalone decompile all functions function.

    This test verifies that:
    - All functions in a binary are properly decompiled
    - Function names and key symbols appear in output
    """
    program_file = os.path.join(ASSETS_DIR, "hello.x64.elf")
    decompilation_results = decompile_all_functions(program_file, language=None)
    main_cb_key = f"func_{0x12c7}"
    assert main_cb_key in decompilation_results
    assert "main" in decompilation_results[main_cb_key]
    assert "printf" in decompilation_results[main_cb_key]


@pytest.mark.parametrize("arch, expected_processor_id", ARCH_INFO_TEST_CASES)
def test_arch_info_to_processor_id(arch, expected_processor_id):
    """
    Test architecture info to processor ID mapping.

    This test verifies that:
    - Architecture information is correctly converted to Ghidra processor IDs
    - Endianness and bit width are correctly considered
    """
    assert _arch_info_to_processor_id(arch) == expected_processor_id


@pytest.fixture
async def program_resource(ofrak_context: OFRAKContext):
    # program compiled from examples/src
    return await ofrak_context.create_root_resource_from_file(
        os.path.join(os.path.dirname(__file__), "assets/program")
    )


async def test_PIE_code_regions(program_resource):
    """
    Test code region handling in Position Independent Executables (PIE).

    This test verifies that:
    - Code regions are correctly created at expected virtual addresses
    - PIE binary base address (0x100000) is properly handled
    - Code region addresses and sizes match expected values

    Requirements Mapping:
    - REQ1.2
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


@pytest.fixture
async def freertos_resource(ofrak_context: OFRAKContext):
    # program compiled from https://github.com/FreeRTOS/FreeRTOS/tree/main/FreeRTOS-Plus/Demo/FreeRTOS_Plus_TCP_Echo_Qemu_mps2
    return await ofrak_context.create_root_resource_from_file(
        os.path.join(os.path.dirname(__file__), "assets/freertos_tcp_mps2_demo.axf")
    )


async def test_strings_in_decomp(freertos_resource, ofrak_injector):
    """
    Test string handling in Ghidra decompilation.

    This test verifies that:
    - String literals appear correctly in decompilation output
    - Symbol names and cross-references are properly preserved
    - Embedded system binaries (FreeRTOS) are correctly handled
    """
    await freertos_resource.unpack_recursively()
    complex_block = await freertos_resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            attribute_filters=(
                ResourceAttributeValueFilter(ComplexBlock.Symbol, "main_tcp_echo_client_tasks"),
            )
        ),
    )
    await complex_block.resource.run(PyGhidraDecompilationAnalyzer)
    decomp_resource: DecompilationAnalysis = await complex_block.resource.view_as(
        DecompilationAnalysis
    )
    decompilation_output = decomp_resource.decompilation
    # check for strings in decompilation:
    assert "Seed for randomiser: " in decompilation_output
    assert "main_tcp_echo_client_tasks" in decompilation_output
    assert "FreeRTOS_IPInit" in decompilation_output
    assert "vTaskStartScheduler" in decompilation_output
    # check for symbol names in cross-references:
    assert "&xInterfaces" in decompilation_output
    assert "&xEndPoints" in decompilation_output
    assert "&ucIPAddress" in decompilation_output
    assert "&ucNetMask" in decompilation_output
    assert "&ucGatewayAddress" in decompilation_output
    assert "&ucDNSServerAddress" in decompilation_output
    assert "&ucMACAddress" in decompilation_output
    assert "usleep(1000000);" in decompilation_output


@pytest.fixture
async def ihex_resource(ofrak_context: OFRAKContext):
    return await ofrak_context.create_root_resource_from_file(
        os.path.join(
            os.path.dirname(__file__),
            "../../ofrak_core/tests/components/assets/hello_world.ihex",
        )
    )


async def test_ihex_unpacking(ihex_resource):
    """
    Test that adding ProgramAttributes to an Ihex file allows for unpacking with ofrak_pyghidra.

    This test verifies that:
    - Intel HEX files can be unpacked with PyGhidra when ProgramAttributes are provided
    - Complex blocks are correctly identified after recursive unpacking
    - Expected function names are discovered in the unpacked binary

    Requirements Mapping:
    - REQ1.2
    """
    program_attributes = ProgramAttributes(
        InstructionSet.X86,
        bit_width=BitWidth.BIT_64,
        endianness=Endianness.LITTLE_ENDIAN,
        sub_isa=None,
        processor=None,
    )
    ihex_resource.add_attributes(program_attributes)
    await ihex_resource.save()
    await ihex_resource.unpack_recursively()

    complex_blocks: List[ComplexBlock] = await ihex_resource.get_descendants_as_view(
        ComplexBlock,
        r_filter=ResourceFilter(
            tags=[
                ComplexBlock,
            ]
        ),
    )
    assert any(cb.name == "FUN_0040040c" for cb in complex_blocks)
    assert any(cb.name == "FUN_004003be" for cb in complex_blocks)


async def test_pyghidra_custom_loader(custom_binary_resource):
    """
    Test that loading a binary with manually-defined MemoryRegions with the PyGhidraCustomLoadAnalyzer results in the right representation in OFRAK.

    This test verifies that:
    - a binary with a custom layout (a code region and a data region) can be loaded into OFRAK and MemoryRegions can be created
    - the program can then be analyzed with the PyGhidraCustomLoadAnalyzer, taking into account the MemoryRegions
    - a specific ComplexBlock can be retrieved and has the right name (meaning it is located at the correct virtual address in PyGhidra)
    - this ComplexBlock can be decompiled and correctly references strings from the data region

    The idea is that the ComplexBlock representation will only be correct if the right raw data is loaded at the right virtual address in PyGhidra. Additionally, the string reference will only show up in the ComplexBlock decompilation if the data region was loaded at the right virtual address in PyGhidra.
    """
    custom_binary_resource.add_tag(Program)
    await custom_binary_resource.save()
    await custom_binary_resource.identify()

    program_attributes = ProgramAttributes(
        isa=InstructionSet.AARCH64,
        sub_isa=SubInstructionSet.ARMv8A,
        bit_width=BitWidth.BIT_64,
        endianness=Endianness.LITTLE_ENDIAN,
        processor=None,
    )
    custom_binary_resource.add_attributes(program_attributes)
    await custom_binary_resource.save()

    # Manually create CodeRegion for .text and MemoryRegion for .rodata
    text_offset = 0
    text_vaddr = 0x400130
    text_size = 40792
    text_section = await custom_binary_resource.create_child(
        tags=(CodeRegion,),
        data_range=Range.from_size(text_offset, text_size),
    )
    text_section.add_view(
        CodeRegion(
            virtual_address=text_vaddr,
            size=text_size,
        )
    )
    await text_section.save()

    gap_size = 0x1234
    rodata_offset = text_offset + text_size + gap_size
    rodata_vaddr = 0x40A0A0
    rodata_size = 7052
    rodata_section = await custom_binary_resource.create_child(
        tags=(MemoryRegion,),
        data_range=Range.from_size(rodata_offset, rodata_size),
    )
    rodata_section.add_view(
        MemoryRegion(
            virtual_address=rodata_vaddr,
            size=rodata_size,
        )
    )
    await rodata_section.save()

    await custom_binary_resource.run(PyGhidraCustomLoadAnalyzer)

    await text_section.unpack()
    # Complex Block at 0x40088c is a good decomp candidate, as it references strings from the .rodata section.
    cb_addr = 0x40088C
    cb = await custom_binary_resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            tags=[ComplexBlock],
            attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, cb_addr),),
        ),
    )
    assert cb.name == "FUN_0040088c"
    await cb.resource.run(PyGhidraDecompilationAnalyzer)
    decomp_resource: DecompilationAnalysis = await cb.resource.view_as(DecompilationAnalysis)
    decomp_str = decomp_resource.decompilation
    print(decomp_str)
    assert '"tini version 0.19.0"' in decomp_str


async def test_pyghidra_custom_loader_with_program_metadata(custom_binary_resource):
    """Test PyGhidra custom loading with ProgramAttributes + MemoryRegions (REQ2.2)."""
    text_vaddr = 0x400130
    text_section = await setup_program_with_code_region(
        custom_binary_resource, base_address=0x100000, text_vaddr=text_vaddr
    )
    await add_rodata_region(
        custom_binary_resource, rodata_vaddr=0x40A0A0, permissions=MemoryPermissions.R
    )
    assert custom_binary_resource.has_tag(PyGhidraCustomLoadProject)

    await custom_binary_resource.run(PyGhidraCustomLoadAnalyzer)

    await text_section.unpack()
    await assert_complex_block_at_vaddr(custom_binary_resource, text_vaddr)
