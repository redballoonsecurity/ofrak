import subprocess
from typing import Tuple, Dict

import pytest

ofrak_angr = pytest.importorskip("ofrak_angr")
from ofrak import OFRAKContext, Resource, ResourceFilter
from ofrak.core import (
    ElfSymbolType,
    LinkableSymbol,
    LinkableSymbolType,
    ElfSymbolSection,
)


@pytest.fixture(autouse=True)
def ghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_angr)


@pytest.fixture(scope="function")
async def unstripped_elf_resource(ofrak_context: OFRAKContext, elf_executable_file) -> Resource:
    return await ofrak_context.create_root_resource_from_file(elf_executable_file)


def readelf_get_writable_sections(elf_executable_file) -> Dict[int, bool]:
    args = ["/usr/bin/readelf", "--sections", "--wide", elf_executable_file]
    proc = subprocess.run(args, stdout=subprocess.PIPE, encoding="utf-8", check=True)
    lines = proc.stdout.split("\n")
    result = dict()
    for line in lines:
        lstripped_line = line.lstrip()
        if len(lstripped_line) == 0:
            continue
        if (
            lstripped_line.startswith("Section Headers:")
            or lstripped_line.startswith("There are")
            or "Nr]" in lstripped_line
        ):
            continue
        if "NULL" in lstripped_line:
            continue
        if lstripped_line.startswith("Key to Flags"):
            break

        _num, name, section_type, addr, offset, size, es, *flg_lk_inf_al = lstripped_line.split()

        if len(flg_lk_inf_al) == 0 or not flg_lk_inf_al[0].isalpha():
            continue
        section_flags = flg_lk_inf_al[0]
        num = int(_num.strip("[]"))
        result[num] = "W" in section_flags

    return result


@pytest.fixture()
async def expected_symbols(elf_executable_file) -> Dict[str, Tuple[int, LinkableSymbolType]]:
    """
    Extract the symbols via readelf
    Symbol table '.symtab' contains 166 entries:
       Num:    Value  Size Type    Bind   Vis      Ndx Name
         0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
         1: 00000000     0 FILE    LOCAL  DEFAULT  ABS adler32.c
         2: 00000000     0 SECTION LOCAL  DEFAULT    1 .text
         3: 00000000     0 SECTION LOCAL  DEFAULT    2 .debug_sfnames
    etc.
    """
    section_is_writable = readelf_get_writable_sections(elf_executable_file)
    args = ["/usr/bin/readelf", "--syms", "--wide", elf_executable_file]
    proc = subprocess.run(args, stdout=subprocess.PIPE, encoding="utf-8", check=True)
    lines = proc.stdout.split("\n")
    result = dict()
    for line in lines:
        lstripped_line = line.lstrip()
        if lstripped_line.startswith("Symbol table") or lstripped_line.startswith("Num:"):
            continue
        tokens = line.split()
        if len(tokens) == 0 or len(tokens) == 7:
            continue

        _, vaddr, _, elf_sym_type, _, _, sh_ndx, *name_elements = tuple(tokens)
        if sh_ndx == "UND":
            continue

        if elf_sym_type == "FUNC":
            sym_type = LinkableSymbolType.FUNC
        elif elf_sym_type == "OBJECT":
            if section_is_writable.get(int(sh_ndx)):
                sym_type = LinkableSymbolType.RW_DATA
            else:
                sym_type = LinkableSymbolType.RO_DATA
        else:
            continue

        name = name_elements[0].split("@")[0]
        result[name] = (int(vaddr, 16), sym_type)

    return result


async def test_complex_block_symbolic_analysis(
    unstripped_elf_resource: Resource,
    expected_symbols: Dict[str, Tuple[int, ElfSymbolType]],
):
    await unstripped_elf_resource.unpack_recursively(do_not_unpack=(ElfSymbolSection,))
    analyzed_syms = await unstripped_elf_resource.get_descendants_as_view(
        LinkableSymbol,
        r_filter=ResourceFilter(
            tags=(LinkableSymbol,),
        ),
    )

    analyzed_syms = list(analyzed_syms)
    assert len(analyzed_syms) != 0

    analyzed_syms_by_name: Dict[str, LinkableSymbol] = {sym.name: sym for sym in analyzed_syms}

    for sym_name, (expected_vaddr, expected_type) in expected_symbols.items():
        if expected_type is not ElfSymbolType.FUNC:
            continue
        assert sym_name in analyzed_syms_by_name
        analyzed_sym = analyzed_syms_by_name[sym_name]
        assert analyzed_sym.virtual_address == expected_vaddr
        assert analyzed_sym.symbol_type == expected_type

    assert "foo" in analyzed_syms_by_name
