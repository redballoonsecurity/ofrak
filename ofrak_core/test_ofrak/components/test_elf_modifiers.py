import os
import subprocess
from typing import Optional

import pytest
from elftools.elf.elffile import ELFFile
from test_ofrak.components.hello_world_elf import hello_elf

from ofrak.core import (
    LiefAddSegmentConfig,
    LiefAddSegmentModifier,
    LiefAddSectionModifer,
    LiefAddSectionModifierConfig,
    LiefRemoveSectionModifier,
    LiefRemoveSectionModifierConfig,
)
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.elf.model import (
    Elf,
    ElfRelaSection,
    ElfRelaEntry,
    ElfDynamicSection,
    ElfDynamicEntry,
    ElfPointerArraySection,
    ElfVirtualAddress,
    ElfProgramHeader,
)
from ofrak.core.elf.modifier import (
    ElfAddStringModifier,
    ElfAddStringModifierConfig,
    ElfRelocateSymbolsModifier,
    ElfRelocateSymbolsModifierConfig,
    ElfRelaModifierConfig,
    ElfRelaModifier,
    ElfDynamicEntryModifier,
    ElfDynamicEntryModifierConfig,
    ElfVirtualAddressModifier,
    ElfVirtualAddressModifierConfig,
    ElfProgramHeaderModifier,
    ElfProgramHeaderModifierConfig,
    ElfPointerArraySectionAddModifier,
    ElfPointerArraySectionAddModifierConfig,
)
from ofrak import OFRAKContext, Resource


async def test_elf_add_symbols(
    ofrak_context: OFRAKContext, elf_executable_file, elf_test_directory
):
    strings_result = subprocess.run(["strings", elf_executable_file], capture_output=True)
    original_strings = set(strings_result.stdout.decode().split("\n"))

    strings_to_add = (
        "yummy",
        "This is a test of the automated string insertion system",
        "really cool information",
    )

    assert not any(s in original_strings for s in strings_to_add)

    original_elf = await ofrak_context.create_root_resource_from_file(elf_executable_file)
    await original_elf.unpack()

    await original_elf.run(ElfAddStringModifier, ElfAddStringModifierConfig(strings_to_add))

    output_path = os.path.join(elf_test_directory, "program_with_newstrings")
    await original_elf.flush_data_to_disk(output_path)
    strings_result = subprocess.run(["strings", output_path], capture_output=True)
    new_strings = set(strings_result.stdout.decode().split("\n"))

    assert new_strings.difference(original_strings) == set(strings_to_add)

    result = subprocess.run([os.path.join(elf_test_directory, "program")])
    assert result.returncode == 12


@pytest.mark.skipif_windows
async def test_elf_force_relocation(
    ofrak_context: OFRAKContext, elf_object_file, elf_test_directory
):
    # Modify this object file so main calls `bar` instead of `foo`
    # This causes the process to exit with code 24 instead of 12
    original_elf = await ofrak_context.create_root_resource_from_file(elf_object_file)
    await original_elf.unpack()

    elf = await original_elf.view_as(Elf)
    symbol_section = await elf.get_symbol_section()
    foo_vaddr = None
    bar_vaddr = None
    for symbol in await symbol_section.get_symbols():
        symbol_name = await symbol.get_name()
        if symbol_name == "foo":
            foo_vaddr = symbol.st_value
        if symbol_name == "bar":
            bar_vaddr = symbol.st_value

    assert foo_vaddr is not None and bar_vaddr is not None

    await elf.resource.run(
        ElfRelocateSymbolsModifier,
        ElfRelocateSymbolsModifierConfig({foo_vaddr: bar_vaddr, bar_vaddr: foo_vaddr}),
    )

    await elf.resource.flush_data_to_disk(os.path.join(elf_test_directory, "program_relocated.o"))
    subprocess.run(["make", "-C", elf_test_directory, "program_relocated"])
    result = subprocess.run([os.path.join(elf_test_directory, "program_relocated")])
    assert result.returncode == 24


MODIFIER_VIEWS_UNDER_TEST = [
    (
        ElfRelaModifier,
        ElfRelaModifierConfig(0xDEADBEEF, 0xFEEDFACE, 0x12345678),
        ElfRelaSection,
        ElfRelaEntry(0xDEADBEEF, 0xFEEDFACE, 0x12345678),
    ),
    (
        ElfDynamicEntryModifier,
        ElfDynamicEntryModifierConfig(0xDEADBEEF, 0x12345678),
        ElfDynamicSection,
        ElfDynamicEntry(0xDEADBEEF, 0x12345678),
    ),
    (
        ElfVirtualAddressModifier,
        ElfVirtualAddressModifierConfig(0xDEADBEEF),
        ElfPointerArraySection,
        ElfVirtualAddress(0xDEADBEEF),
    ),
]


@pytest.mark.parametrize(
    "modifier, modifier_config, test_view, test_view_entry", MODIFIER_VIEWS_UNDER_TEST
)
async def test_modifier(
    ofrak_context: OFRAKContext,
    elf_executable_file,
    elf_test_directory,
    modifier,
    modifier_config,
    test_view,
    test_view_entry,
):
    original_elf = await ofrak_context.create_root_resource_from_file(elf_executable_file)
    await original_elf.unpack()
    elf = await original_elf.view_as(Elf)
    views = list(
        await original_elf.get_children_as_view(
            test_view,
            ResourceFilter(tags=(test_view,)),
        )
    )
    assert len(views) > 0
    for view in views:
        for entry in await view.get_entries():
            await entry.resource.run(modifier, modifier_config)
    mod_path = elf_executable_file + "_mod"
    await elf.resource.flush_data_to_disk(mod_path)
    mod_elf = await ofrak_context.create_root_resource_from_file(mod_path)
    await mod_elf.unpack()
    views = list(
        await mod_elf.get_children_as_view(
            test_view,
            ResourceFilter(tags=(test_view,)),
        )
    )
    for view in views:
        for entry in await view.get_entries():
            assert entry == test_view_entry


@pytest.fixture
async def elf_resource(elf_executable_file: str, ofrak_context: OFRAKContext):
    return await ofrak_context.create_root_resource_from_file(elf_executable_file)


async def test_elf_program_header_modifier(elf_resource: Resource):
    """
    Test the ElfProgramHeaderModifier.
    """
    await elf_resource.unpack()
    elf = await elf_resource.view_as(Elf)
    for program_header in await elf.get_program_headers():
        assert program_header.p_type != 0x1337
        await program_header.resource.run(
            ElfProgramHeaderModifier, ElfProgramHeaderModifierConfig(0x1337)
        )
        updated_program_header = await program_header.resource.view_as(ElfProgramHeader)
        assert updated_program_header.p_type == 0x1337


class TestElfPointerArraySectionModifier:
    add_value = 0x1337

    async def test_elf_pointer_array_section_modifier(self, elf_resource: Resource):
        """
        Test that `ElfPointerArraySectionModifier` modifies the underlying pointer bytes.
        """
        pointer_array_section = await self._unpack_and_get_first_pointer_array_section(elf_resource)
        original_data_values = list()
        for entry in await pointer_array_section.get_entries():
            original_data = await entry.resource.get_data()
            original_data_values.append(original_data)

        await pointer_array_section.resource.run(
            ElfPointerArraySectionAddModifier,
            ElfPointerArraySectionAddModifierConfig(skip_list=(), add_value=self.add_value),
        )
        updated_pointer_array_section = await pointer_array_section.resource.view_as(
            ElfPointerArraySection
        )

        for i, entry in enumerate(await updated_pointer_array_section.get_entries()):
            new_data = await entry.resource.get_data()
            assert new_data != original_data_values[i]

    async def _unpack_and_get_first_pointer_array_section(self, elf_resource):
        await elf_resource.unpack()
        pointer_array_section = list(
            await elf_resource.get_descendants_as_view(
                ElfPointerArraySection, r_filter=ResourceFilter.with_tags(ElfPointerArraySection)
            )
        )[0]
        return pointer_array_section


@pytest.fixture
async def hello_out(ofrak_context: OFRAKContext) -> Resource:
    return await ofrak_context.create_root_resource("hello.out", hello_elf())


async def test_lief_add_segment_modifier(hello_out: Resource, tmp_path):
    """
    Test that adding a segment results in a new segment in the Elf with the given vaddr and length.
    """
    segment_vaddr = 0x108000
    segment_length = 0x2000

    # Assert new segment not in original binary
    original_path = tmp_path / "original"
    await hello_out.flush_data_to_disk(original_path)
    with pytest.raises(ValueError):
        assert_segment_exists(original_path, segment_vaddr, segment_length)

    # Add segment
    config = LiefAddSegmentConfig(segment_vaddr, 0x1000, [0 for _ in range(segment_length)], "rw")
    await hello_out.run(LiefAddSegmentModifier, config)

    # Assert new segment is in extended binary
    extended_path = tmp_path / "extended"
    await hello_out.flush_data_to_disk(extended_path)
    assert_segment_exists(extended_path, segment_vaddr, 0x2000)


def assert_segment_exists(filepath: str, vaddr: int, length: int):
    """
    Assert segment with given vaddr and length exist.
    """
    with open(filepath, "rb") as f:
        elffile = ELFFile(f)
        segments = list(elffile.iter_segments())
        for segment in segments:
            if segment.header.p_vaddr == vaddr and segment.header.p_memsz == length:
                return
        raise ValueError("Could not find segment in binary")


async def test_lief_add_section_modifier(hello_out: Resource, tmp_path):
    config = LiefAddSectionModifierConfig(name=".test", content=b"test", flags=0)
    await hello_out.run(LiefAddSectionModifer, config=config)
    elf_path = tmp_path / "test.elf"
    await hello_out.flush_data_to_disk(elf_path)
    assert segment_exists(elf_path, ".test", content=b"test")


async def test_lief_remove_section_modifier(hello_out: Resource, tmp_path):
    original = tmp_path / "original.elf"
    await hello_out.flush_data_to_disk(original)
    assert segment_exists(original, ".text")
    config = LiefRemoveSectionModifierConfig(name=".text")
    await hello_out.run(LiefRemoveSectionModifier, config=config)
    modified = tmp_path / "modified.elf"
    await hello_out.flush_data_to_disk(modified)
    assert not segment_exists(modified, ".text")


def segment_exists(filepath: str, name: str, content: Optional[bytes] = None):
    with open(filepath, "rb") as f:
        elffile = ELFFile(f)
        sections = list(elffile.iter_sections())
        for section in sections:
            if section.name == name:
                if content is not None and content in section.data():
                    return True
                if content is None:
                    return True
    return False
