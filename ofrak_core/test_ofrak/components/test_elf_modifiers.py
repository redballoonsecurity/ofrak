import os
import subprocess

import pytest

from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.elf.model import (
    Elf,
    ElfRelaSection,
    ElfRelaEntry,
    ElfDynamicSection,
    ElfDynamicEntry,
    ElfPointerArraySection,
    ElfVirtualAddress,
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
)
from ofrak import OFRAKContext


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
    await original_elf.flush_to_disk(output_path)
    strings_result = subprocess.run(["strings", output_path], capture_output=True)
    new_strings = set(strings_result.stdout.decode().split("\n"))

    assert new_strings.difference(original_strings) == set(strings_to_add)

    result = subprocess.run([os.path.join(elf_test_directory, "program")])
    assert result.returncode == 12


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

    await elf.resource.flush_to_disk(os.path.join(elf_test_directory, "program_relocated.o"))
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
    await elf.resource.flush_to_disk(mod_path)
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
