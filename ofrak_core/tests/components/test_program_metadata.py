"""
Test the entry_points and base_address fields on ProgramAttributes,
and the format-specific analyzers that populate them.

Requirements Mapping:
- REQ2.2
"""
import os


from ofrak import OFRAKContext
from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))


def test_program_attributes_metadata_defaults():
    """New fields default to empty/None, preserving backwards compatibility."""
    attrs = ProgramAttributes(
        InstructionSet.X86, None, BitWidth.BIT_64, Endianness.LITTLE_ENDIAN, None
    )
    assert attrs.entry_points == ()
    assert attrs.base_address is None


def test_program_attributes_with_metadata():
    """entry_points and base_address can be set explicitly."""
    attrs = ProgramAttributes(
        InstructionSet.X86,
        None,
        BitWidth.BIT_64,
        Endianness.LITTLE_ENDIAN,
        None,
        entry_points=(0x1000, 0x2000),
        base_address=0x400000,
    )
    assert attrs.entry_points == (0x1000, 0x2000)
    assert attrs.base_address == 0x400000


class TestElfProgramAttributesAnalyzer:
    """Tests for ElfProgramAttributesAnalyzer entry_points and base_address."""

    async def test_elf_program_attributes_hello_out(self, ofrak_context: OFRAKContext):
        """Test correct values from hello.out."""
        filepath = os.path.join(ASSETS_DIR, "hello.out")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()
        attrs = await resource.analyze(ProgramAttributes)
        assert attrs.entry_points == (0x4003E0,)
        assert attrs.base_address == 0x400000

    async def test_elf_program_attributes_arm(self, ofrak_context: OFRAKContext):
        """Test correct values from ARM ELF."""
        filepath = os.path.join(ASSETS_DIR, "arm_reloc_relocated.elf")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()
        attrs = await resource.analyze(ProgramAttributes)
        assert attrs.entry_points == (0x8104,)
        assert attrs.base_address == 0x0

    async def test_elf_no_pt_load(self, ofrak_context: OFRAKContext):
        """Relocatable .o has no PT_LOAD → base_address=None."""
        filepath = os.path.join(
            os.path.dirname(__file__),
            "../../../pytest_ofrak/src/pytest_ofrak/elf/assets/program.o",
        )
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()
        attrs = await resource.analyze(ProgramAttributes)
        assert attrs.entry_points == (0x0,)
        assert attrs.base_address is None

    async def test_elf_entry_point_zero(self, ofrak_context: OFRAKContext):
        """ELF e_entry=0 is valid (unlike PE where entry_rva=0 means 'no entry')."""
        filepath = os.path.join(ASSETS_DIR, "entry_at_zero.elf")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()
        attrs = await resource.analyze(ProgramAttributes)
        assert attrs.entry_points == (0x0,)


class TestUImageProgramAttributesAnalyzer:
    async def test_uimage_program_attributes(self, ofrak_context: OFRAKContext):
        """UImage header ih_ep and ih_load are extracted."""
        filepath = os.path.join(ASSETS_DIR, "uimage")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()
        attrs = await resource.analyze(ProgramAttributes)
        assert attrs.entry_points == (0x0,)
        assert attrs.base_address == 0x0


class TestIhexStartAddress:
    """IHEX start_addr is available via the Ihex view (no separate analyzer)."""

    async def test_ihex_start_addr_present(self, ofrak_context: OFRAKContext):
        from ofrak.core.ihex import Ihex

        filepath = os.path.join(ASSETS_DIR, "hello_world.ihex")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()
        ihex = await resource.view_as(Ihex)
        assert ihex.start_addr == 0x4003E0

    async def test_ihex_no_start_address(self, ofrak_context: OFRAKContext):
        import bincopy
        from ofrak.core.ihex import Ihex

        bf = bincopy.BinFile()
        bf.add_binary(b"\x00" * 16, address=0x1000)
        ihex_data = bf.as_ihex().encode("ascii")
        resource = await ofrak_context.create_root_resource("no_start.ihex", ihex_data)
        await resource.unpack_recursively()
        ihex = await resource.view_as(Ihex)
        assert ihex.start_addr is None
