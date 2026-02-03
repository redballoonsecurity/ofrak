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


class TestPeProgramMetadataAnalyzer:
    """Tests for PeProgramMetadataAnalyzer."""

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
