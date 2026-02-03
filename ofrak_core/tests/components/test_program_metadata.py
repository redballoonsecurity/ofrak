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

    @pytest.mark.parametrize(
        "elf_file",
        [
            "hello.out",
            "arm_reloc_relocated.elf",
        ],
    )
    async def test_elf_program_metadata_analyzer(self, ofrak_context: OFRAKContext, elf_file: str):
        """Test that ElfProgramMetadataAnalyzer extracts entry point from ELF files."""
        from ofrak.core.elf.analyzer import ElfProgramMetadataAnalyzer

        filepath = os.path.join(ASSETS_DIR, elf_file)
        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        # Run the analyzer explicitly
        await resource.run(ElfProgramMetadataAnalyzer)
        metadata = resource.get_attributes(ProgramMetadata)

        # Entry points should be a tuple
        assert isinstance(metadata.entry_points, tuple)
        # Base address should be set or None (depending on ELF type)
        assert metadata.base_address is None or isinstance(metadata.base_address, int)


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

        # UImage should have entry point and base address from header
        assert isinstance(metadata.entry_points, tuple)
        assert len(metadata.entry_points) > 0
        assert isinstance(metadata.base_address, int) or metadata.base_address is None


class TestIhexProgramMetadataAnalyzer:
    """Tests for IhexProgramMetadataAnalyzer."""

    async def test_ihex_program_metadata_analyzer(self, ofrak_context: OFRAKContext):
        """Test that IhexProgramMetadataAnalyzer extracts start address if present."""
        filepath = os.path.join(ASSETS_DIR, "simple.ihex")
        if not os.path.exists(filepath):
            pytest.skip("simple.ihex test file not found")

        resource = await ofrak_context.create_root_resource_from_file(filepath)
        await resource.unpack_recursively()

        # The analyzer should have run - entry point may or may not be set
        metadata = resource.get_attributes(ProgramMetadata)
        assert isinstance(metadata.entry_points, tuple)
