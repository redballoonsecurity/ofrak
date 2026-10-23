"""
This module tests DerivedReferencedStringsAnalyzer, which derives which functions reference which
strings from the function→data cross-references of a disassembler backend.

Requirements Mapping:
- REQ2.2
- REQ2.5
"""
import os

import pytest
from elftools.elf.elffile import ELFFile

from ofrak import OFRAKContext, ResourceFilter
from ofrak.core import (
    BinaryPatchConfig,
    BinaryPatchModifier,
    CodeRegion,
    ComplexBlock,
    DerivedReferencedStringsAnalyzer,
    Elf,
    ElfSection,
    ElfSegment,
    Program,
    ReferencedDataAttributes,
    ReferencedDataUnavailableError,
    ReferencedStringsAttributes,
    get_function_string_references,
)
from pytest_ofrak import ASSETS_DIR as PYTEST_OFRAK_ASSETS_DIR
from .re_markup_experiment import ASSETS_DIR, BUILD_A, analyze_build, load_ground_truth

COMPONENTS_ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")
# A bare-metal Cortex-M style program, whose functions load the address of a string, and that of a
# RAM variable which reads like a string, from literal pools (see fw-cortex-m.c)
FIRMWARE = os.path.join(ASSETS_DIR, "fw-cortex-m.elf")
# A position-independent ARM program, whose literal pools hold offsets that, read as addresses, are
# inside strings (see arm-pie.c)
ARM_PIE = os.path.join(ASSETS_DIR, "arm-pie.elf")

# Strings that functions of Lua 5.4.7's lauxlib.c pass to luaL_error / lua_pushfstring
KNOWN_FUNCTION_STRINGS = {
    "luaL_argerror": (
        "bad argument #%d (%s)",
        "bad argument #%d to '%s' (%s)",
        "calling '%s' on bad self (%s)",
        "method",
    ),
    "luaL_checkversion_": (
        "core and library have incompatible numeric types",
        "version mismatch: app. needs %f, Lua core provides %f",
    ),
}


async def _get_strings_by_function_name(root):
    strings_by_function = await get_function_string_references(await root.view_as(Program))
    names = {
        complex_block.virtual_address: complex_block.name
        for complex_block in await root.get_descendants_as_view(
            ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
    }
    return {names[vaddr]: strings for vaddr, strings in strings_by_function.items()}


async def test_known_functions_reference_known_strings(ghidra_ofrak_context: OFRAKContext):
    """
    Test that the strings derived for known functions of a real binary are the strings those
    functions use in their source code (REQ2.5).

    This test verifies that:
    - Functions are identified by the virtual address of their complex block
    - Each known function references exactly the string literals of its source code
    """
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    ground_truth = load_ground_truth(BUILD_A)
    strings_by_function = await get_function_string_references(await root.view_as(Program))

    for function_name, expected_strings in KNOWN_FUNCTION_STRINGS.items():
        function_vaddr = ground_truth.unique_vaddr(function_name)
        assert strings_by_function[function_vaddr] == expected_strings


async def test_referenced_strings_attributes(ghidra_ofrak_context: OFRAKContext):
    """
    Test the ReferencedStringsAttributes derived for a real binary against the binary itself
    (REQ2.2, REQ2.5).

    This test verifies that:
    - Every referencing function is the start of a complex block
    - Every referenced string is the virtual address range of a NUL-terminated, printable string
      in a section of the ELF loaded in memory (not, say, its symbol names)
    - No string is an entry of a pointer or jump table: a pointer-aligned string short enough to
      be a pointer never reads as the address of a loaded section
    - The edges are unique, sorted, and point to valid functions and strings
    - Running the analyzer again gives the same attributes
    """
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    await root.run(DerivedReferencedStringsAnalyzer)
    attributes = root.get_attributes(ReferencedStringsAttributes)

    complex_block_vaddrs = {
        complex_block.virtual_address
        for complex_block in await root.get_descendants_as_view(
            ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
    }
    assert set(attributes.referencing_functions) <= complex_block_vaddrs
    assert len(attributes.referencing_functions) > 100

    with open(BUILD_A.path, "rb") as f:
        loaded_sections = [
            (section["sh_addr"], section.data())
            for section in ELFFile(f).iter_sections()
            if section["sh_flags"] & 0x2 and section["sh_type"] != "SHT_NOBITS"
        ]

    def find_loaded(vaddr):
        for section_vaddr, data in loaded_sections:
            if section_vaddr <= vaddr < section_vaddr + len(data):
                return data, vaddr - section_vaddr
        return None

    for string_range in attributes.referenced_strings:
        data, offset = find_loaded(string_range.start)
        string_bytes = data[offset : offset + string_range.length() + 1]
        # The range covers the text, and the NUL terminator follows it
        assert string_range.length() >= 2
        assert string_bytes.endswith(b"\x00")
        assert b"\x00" not in string_bytes[:-1]
        text = string_bytes[:-1].decode("utf-8")
        assert all(character.isprintable() or character in "\t\n\r" for character in text)
        if len(string_bytes) <= 8 and string_range.start % 8 == 0:
            pointer = int.from_bytes(data[offset : offset + 8], "little")
            assert find_loaded(pointer) is None, text

    assert list(attributes.references) == sorted(set(attributes.references))
    for function_index, string_index in attributes.references:
        assert 0 <= function_index < len(attributes.referencing_functions)
        assert 0 <= string_index < len(attributes.referenced_strings)

    await root.run(DerivedReferencedStringsAnalyzer)
    assert root.get_attributes(ReferencedStringsAttributes) == attributes


async def test_position_independent_executable(ghidra_ofrak_context: OFRAKContext):
    """
    Test that strings are found in a position-independent executable, which the Ghidra backend
    loads at another address than the file's (REQ2.5).

    This test verifies that:
    - The backend moved the code to other addresses than its section's
    - The function's string is found anyway, from the backend's addresses
    """
    root = await ghidra_ofrak_context.create_root_resource_from_file(
        os.path.join(COMPONENTS_ASSETS_DIR, "elf", "hello_elf_dyn")
    )
    await root.unpack()
    strings_by_function = await _get_strings_by_function_name(root)

    moved = []
    for code_region in await root.get_children_as_view(
        CodeRegion, r_filter=ResourceFilter.with_tags(CodeRegion)
    ):
        section = await code_region.resource.view_as(ElfSection)
        if code_region.virtual_address != (await section.get_header()).sh_addr:
            moved.append(section.name)
    assert ".text" in moved
    assert strings_by_function["main"] == ("Hello, World!",)


async def test_executable_without_sections(ghidra_ofrak_context: OFRAKContext):
    """
    Test that strings are found in an executable without section headers, whose code regions
    are its loadable segments (REQ2.5).

    This test verifies that:
    - The program's code regions are ELF segments
    - The main function references its string
    """
    root = await ghidra_ofrak_context.create_root_resource_from_file(
        os.path.join(COMPONENTS_ASSETS_DIR, "hello_nosections.out")
    )
    await root.unpack()
    strings_by_function = await get_function_string_references(await root.view_as(Program))

    code_regions = list(
        await root.get_children_as_view(CodeRegion, r_filter=ResourceFilter.with_tags(CodeRegion))
    )
    assert code_regions and all(cr.resource.has_tag(ElfSegment) for cr in code_regions)
    assert strings_by_function[0x4004C4] == ("Hello World",)


async def test_firmware_literal_pools_are_not_strings(ghidra_ofrak_context: OFRAKContext):
    """
    Test the strings of firmware whose functions load addresses from literal pools (REQ2.5).

    This test verifies that:
    - A function references a literal pool word whose bytes read like a NUL-terminated string,
      because it holds the address of a .bss variable, which has no data in the file: it is not
      taken for a string
    - The string literal whose address another function loads from its literal pool is a string
      that function references, through the reference the backend made from the load
    """
    root = await ghidra_ofrak_context.create_root_resource_from_file(FIRMWARE)
    await root.unpack()
    strings_by_function = await _get_strings_by_function_name(root)

    data_refs = await root.analyze(ReferencedDataAttributes)
    with open(FIRMWARE, "rb") as f:
        text = ELFFile(f).get_section_by_name(".text")
        text_vaddr, text_data = text["sh_addr"], text.data()
    pool_words = [
        vaddr
        for vaddrs in data_refs.get_xrefs_from().values()
        for vaddr in vaddrs
        if 0 <= vaddr - text_vaddr < len(text_data)
        and text_data[vaddr - text_vaddr :].startswith(b"@A\x00")
    ]
    assert pool_words
    assert strings_by_function == {"boot": ("Image signature invalid",)}


async def test_position_independent_arm_code(ghidra_ofrak_context: OFRAKContext):
    """
    Test that each function of position-independent ARM code references the strings it uses, and
    no others (REQ2.5).

    This test verifies that:
    - Words of the code (the offsets in literal pools from which the functions compute the
      addresses of their strings) are, read as addresses, inside the strings of .rodata
    - Each function references exactly the strings it uses
    """
    root = await ghidra_ofrak_context.create_root_resource_from_file(ARM_PIE)
    await root.unpack()
    strings_by_function = await _get_strings_by_function_name(root)

    with open(ARM_PIE, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text").data()
        rodata = elf.get_section_by_name(".rodata")
        rodata_vaddrs = range(rodata["sh_addr"], rodata["sh_addr"] + rodata["sh_size"])
    words = [
        int.from_bytes(text[offset : offset + 4], "little") for offset in range(0, len(text), 4)
    ]
    assert any(word in rodata_vaddrs for word in words)
    help_texts = strings_by_function.pop("print_help")
    assert len(help_texts) == 23
    assert "Usage: flashtool [OPTION]... IMAGE" in help_texts
    assert strings_by_function == {
        "erase_sectors": ("Cannot erase past the end of the device", "Erasing sectors"),
        "write_image": ("The image is empty", "Writing the image"),
        "verify_image": ("Image verified", "The flash does not hold the image that was written"),
    }


async def test_strings_follow_patches(ghidra_ofrak_context: OFRAKContext):
    """
    Test that the strings of a program are derived again when patching the program changed them
    (REQ2.5).

    This test verifies that:
    - A string shortened by a patch is read as its new text
    - A string that a patch made invalid UTF-8 is no longer a string the function references
    """
    root = await ghidra_ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    assert await _get_strings_by_function_name(root) == {"main": ("Hello World",)}
    rodata = await (await root.view_as(Elf)).get_section_by_name(".rodata")
    offset = (await rodata.resource.get_data()).index(b"Hello World")

    await rodata.resource.run(BinaryPatchModifier, BinaryPatchConfig(offset, b"Bye\x00"))
    assert await _get_strings_by_function_name(root) == {"main": ("Bye",)}

    await rodata.resource.run(BinaryPatchModifier, BinaryPatchConfig(offset, b"H\xe9llo"))
    assert await _get_strings_by_function_name(root) == {}


async def test_program_is_unpacked_for_analysis(ghidra_ofrak_context: OFRAKContext):
    """
    Test that the strings of a program that was only identified are derived once it is unpacked,
    rather than found missing (REQ2.5).

    This test verifies that:
    - Getting the strings of a program without code regions unpacks it into functions
    - Its function references its string
    """
    root = await ghidra_ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.identify()

    assert await _get_strings_by_function_name(root) == {"main": ("Hello World",)}


async def test_blanket_analysis_does_not_run_analyzer(ofrak_context: OFRAKContext):
    """
    Test that analyzing everything that can be analyzed about a program, as the GUI's Analyze
    does, works without a backend that provides data cross-references (REQ2.5).

    This test verifies that:
    - Running all analyzers on a program, and analyzing it recursively, succeed
    - The derived referenced strings are not among the analyses run
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    await root.auto_run(all_analyzers=True)
    await root.analyze_recursively()

    assert not root.has_attributes(ReferencedStringsAttributes)


async def test_no_data_references_backend(ofrak_context: OFRAKContext):
    """
    Test that the analyzer raises a capability error when no backend provides data
    cross-references (REQ2.5).

    This test verifies that:
    - Without the Ghidra or Binary Ninja backend, running the analyzer, or asking for the strings
      of a program's functions, raises ReferencedDataUnavailableError naming the backends that
      provide them
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    with pytest.raises(ReferencedDataUnavailableError, match="Ghidra.*Binary Ninja"):
        await root.run(DerivedReferencedStringsAnalyzer)
    with pytest.raises(ReferencedDataUnavailableError, match="Ghidra.*Binary Ninja"):
        await get_function_string_references(await root.view_as(Program))
