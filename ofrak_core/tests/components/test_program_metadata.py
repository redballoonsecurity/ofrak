"""
Test the ProgramMetadata ResourceAttribute and format-specific analyzers.

Requirements Mapping:
- REQ2.2
"""
import os

import pytest

from ofrak import OFRAKContext
from ofrak.core.program_metadata import ProgramMetadata

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))


class TestProgramMetadataDataclass:
    """Tests for ProgramMetadata dataclass."""

    def test_program_metadata_defaults(self):
        """Test ProgramMetadata with default values."""
        metadata = ProgramMetadata()
        assert metadata.entry_points == ()
        assert metadata.base_address is None

    def test_program_metadata_with_values(self):
        """Test ProgramMetadata with explicit values."""
        metadata = ProgramMetadata(
            entry_points=(0x1000, 0x2000),
            base_address=0x400000,
        )
        assert metadata.entry_points == (0x1000, 0x2000)
        assert metadata.base_address == 0x400000

    def test_program_metadata_frozen(self):
        """Test that ProgramMetadata is frozen (immutable)."""
        metadata = ProgramMetadata(entry_points=(0x1000,), base_address=0x400000)
        with pytest.raises(AttributeError):
            metadata.entry_points = (0x2000,)
        with pytest.raises(AttributeError):
            metadata.base_address = 0x500000

    def test_program_metadata_equality(self):
        """Test ProgramMetadata equality comparison."""
        metadata1 = ProgramMetadata(entry_points=(0x1000,), base_address=0x400000)
        metadata2 = ProgramMetadata(entry_points=(0x1000,), base_address=0x400000)
        metadata3 = ProgramMetadata(entry_points=(0x2000,), base_address=0x400000)

        assert metadata1 == metadata2
        assert metadata1 != metadata3


class TestElfProgramMetadataAnalyzer:
    """Tests for ElfProgramMetadataAnalyzer."""

    async def test_elf_program_metadata_analyzer_hello_out(self, ofrak_context: OFRAKContext):
        """Test that ElfProgramMetadataAnalyzer extracts correct values from hello.out."""
        from ofrak.core.elf.analyzer import ElfProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "hello.out")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        # Run the analyzer explicitly
        await resource.run(ElfProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # Verify concrete expected values
        assert metadata.entry_points == (0x4003E0,)
        assert metadata.base_address == 0x400000

    async def test_elf_program_metadata_analyzer_arm(self, ofrak_context: OFRAKContext):
        """Test that ElfProgramMetadataAnalyzer extracts entry point from ARM ELF."""
        from ofrak.core.elf.analyzer import ElfProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "arm_reloc_relocated.elf")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        # Run the analyzer explicitly
        await resource.run(ElfProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # Verify concrete expected values from readelf output
        assert metadata.entry_points == (0x8104,)
        assert metadata.base_address == 0x0

    async def test_elf_no_pt_load(self, ofrak_context: OFRAKContext):
        """
        Test that ElfProgramMetadataAnalyzer returns base_address=None for ELFs without PT_LOAD.

        Relocatable object files (.o) have no program headers and therefore no PT_LOAD
        segments. The analyzer should return base_address=None in this case.
        """
        from ofrak.core.elf.analyzer import ElfProgramMetadataAnalyzer

        filepath = os.path.join(
            os.path.dirname(__file__),
            "../../../pytest_ofrak/src/pytest_ofrak/elf/assets/program.o",
        )
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        await resource.run(ElfProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # Relocatable .o file has e_entry=0 and no PT_LOAD segments
        assert metadata.entry_points == (0x0,)
        assert metadata.base_address is None


class TestUImageProgramMetadataAnalyzer:
    """Tests for UImageProgramMetadataAnalyzer."""

    async def test_uimage_program_metadata_analyzer(self, ofrak_context: OFRAKContext):
        """Test that UImageProgramMetadataAnalyzer extracts entry and load addresses."""
        from ofrak.core.uimage import UImageProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "uimage")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        # Run the analyzer explicitly
        await resource.run(UImageProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # Verify concrete expected values from UImage header
        # This UImage has ih_ep=0x0 and ih_load=0x0
        assert metadata.entry_points == (0x0,)
        assert metadata.base_address == 0x0


class TestIhexProgramMetadataAnalyzer:
    """Tests for IhexProgramMetadataAnalyzer."""

    async def test_ihex_program_metadata_analyzer(self, ofrak_context: OFRAKContext):
        """Test that IhexProgramMetadataAnalyzer extracts start address if present."""
        from ofrak.core.ihex import IhexProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "hello_world.ihex")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        # Run the analyzer explicitly
        await resource.run(IhexProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # Verify concrete expected value from Intel HEX execution_start_address
        # Value 0x4003E0 from bincopy parsing of hello_world.ihex
        assert metadata.entry_points == (0x4003E0,)
        assert metadata.base_address is None

    async def test_ihex_no_start_address(self, ofrak_context: OFRAKContext):
        """
        Test that IhexProgramMetadataAnalyzer returns empty entry_points when no start address.

        Intel HEX files without a Start Segment Address (type 03) or Start Linear Address
        (type 05) record have no execution start address. The analyzer should return
        empty entry_points in this case.
        """
        import bincopy
        from ofrak.core.ihex import IhexProgramMetadataAnalyzer

        # Create a minimal ihex with data but no start address record
        bf = bincopy.BinFile()
        bf.add_binary(b"\x00" * 16, address=0x1000)
        ihex_data = bf.as_ihex().encode("ascii")
        assert bf.execution_start_address is None  # sanity check

        resource = await ofrak_context.create_root_resource("no_start.ihex", ihex_data)
        await resource.unpack_recursively()

        await resource.run(IhexProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        assert metadata.entry_points == ()
        assert metadata.base_address is None


class TestPeProgramMetadataAnalyzer:
    """Tests for PeProgramMetadataAnalyzer.

    TODO: Add test for PE files that use PeOptionalHeader fallback path (non-Windows PE
    files where PeWinOptionalHeader is not present). This requires a PE test asset that
    only has a base PeOptionalHeader without the Windows-specific extended fields.
    """

    async def test_pe_program_metadata_analyzer(self, ofrak_context: OFRAKContext):
        """Test that PeProgramMetadataAnalyzer extracts entry point and image base from PE files."""
        from ofrak.core.pe.analyzer import PeProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "jumpnbump.exe")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        # Run the analyzer explicitly
        await resource.run(PeProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # PE should have entry point (image_base + RVA) and base address
        assert metadata.entry_points == (0x40C966,)  # 0x400000 + 0xC966
        assert metadata.base_address == 0x400000

    async def test_pe_program_metadata_analyzer_dll_no_entry(self, ofrak_context: OFRAKContext):
        """
        Test that PeProgramMetadataAnalyzer returns empty entry_points for DLLs without entry point.

        For PE files (especially DLLs), AddressOfEntryPoint=0 means "no entry point" - this is
        different from ELF where entry=0 can be a valid address. The analyzer should return
        an empty entry_points tuple in this case, NOT (image_base,).

        This test catches the bug where entry_rva=0 is incorrectly computed as image_base+0.
        """
        from ofrak.core.pe.analyzer import PeProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "no_entry_point.dll")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        await resource.run(PeProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # DLL with no entry point should have empty entry_points, not (image_base,)
        assert metadata.entry_points == ()
        assert metadata.base_address is not None  # image_base should still be present


class TestEntryPointZero:
    """
    Tests for correct handling of entry point address 0.

    Entry point = 0 is valid in some contexts:
    - ELF: Entry = 0 can be valid for relocatable objects or firmware at address 0
    - UImage: Entry = 0 means the kernel/firmware starts at address 0
    - PE: entry_rva = 0 means "no entry point" (different semantics!)
    """

    async def test_uimage_entry_point_zero(self, ofrak_context: OFRAKContext):
        """Test that UImage correctly reports entry point 0 when ih_ep=0."""
        from ofrak.core.uimage import UImageProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "uimage")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        await resource.run(UImageProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # UImage with ih_ep=0 should include 0 in entry_points (it's a valid address)
        assert 0 in metadata.entry_points
        assert metadata.entry_points == (0x0,)

    async def test_elf_entry_point_zero(self, ofrak_context: OFRAKContext):
        """
        Test that ELF correctly reports entry point 0 when e_entry=0.

        Entry point 0 is valid for ELF files - it means execution starts at address 0.
        This is different from PE where entry_rva=0 means "no entry point".
        """
        from ofrak.core.elf.analyzer import ElfProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, "entry_at_zero.elf")
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        await resource.run(ElfProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # ELF with e_entry=0 should include 0 in entry_points (it's a valid address)
        assert 0 in metadata.entry_points
        assert metadata.entry_points == (0x0,)
