"""
Test the Ghidra data references analyzer.
"""
import os

from ofrak import OFRAKContext
from ofrak.core import Elf
from ofrak.core.data import ReferencedDataAttributes
from ofrak.core.elf.model import ElfProgramHeaderType
from pytest_ofrak import ASSETS_DIR
from pytest_ofrak.patterns.data_refs_analyzer import DataRefsAnalyzerTestPattern


class TestGhidraDataRefsAnalyzer(DataRefsAnalyzerTestPattern):
    pass


async def test_data_refs_are_in_loaded_memory(ofrak_context: OFRAKContext):
    """
    Test that GetDataRefs.java only reports references between addresses of the program's loaded
    memory: not those of the ELF headers, which Ghidra marks up outside of it when no segment holds
    them, at offsets that would read as addresses of the program.
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(ASSETS_DIR, "simple_arm_gcc.o.elf")
    )
    await root.unpack()
    data_refs = await root.analyze(ReferencedDataAttributes)

    elf = await root.view_as(Elf)
    loaded = [
        range(header.p_vaddr, header.p_vaddr + header.p_memsz)
        for header in await elf.get_program_headers()
        if header.p_type == ElfProgramHeaderType.LOAD.value
    ]
    references = [
        (from_vaddr, to_vaddr)
        for from_vaddr, to_vaddrs in data_refs.get_xrefs_from().items()
        for to_vaddr in to_vaddrs
    ]
    assert references
    for from_vaddr, to_vaddr in references:
        assert any(from_vaddr in segment for segment in loaded), hex(from_vaddr)
        assert any(to_vaddr in segment for segment in loaded), hex(to_vaddr)
