import logging
import tempfile
from dataclasses import dataclass
from typing import Optional, List

from binaryninja import BinaryView, open_view, BinaryViewType, SegmentFlag

from ofrak import ResourceFilter
from ofrak.component.analyzer import Analyzer
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.code_region import CodeRegion
from ofrak.core.memory_region import (
    MemoryRegion,
    MemoryRegionPermissions,
    get_memory_region_permissions,
)
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributeDependency
from ofrak_binary_ninja.model import (
    BinaryNinjaAutoLoadProject,
    BinaryNinjaCustomLoadProject,
)
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from ofrak.resource import Resource
from ofrak_type.error import NotFoundError
from ofrak_type.memory_permissions import MemoryPermissions

LOGGER = logging.getLogger(__file__)


@dataclass
class BinaryNinjaAnalyzerConfig(ComponentConfig):
    bndb_file: str  # Path to BinaryNinja DB pre-analyzed file


class BinaryNinjaAnalyzer(Analyzer[Optional[BinaryNinjaAnalyzerConfig], BinaryNinjaAnalysis]):
    """
    Opens and analyzes binaries with Binary Ninja, either from scratch or from a pre-analyzed
    BNDB file. Use for auto-loadable formats (ELF, PE, Ihex) where Binary Ninja can automatically
    determine the binary format. Creates BinaryNinjaAnalysis state containing the BinaryView for
    use by other Binary Ninja components.
    """

    id = b"BinaryNinjaAnalyzer"
    targets = (BinaryNinjaAutoLoadProject,)
    outputs = (BinaryNinjaAnalysis,)

    async def analyze(
        self, resource: Resource, config: Optional[BinaryNinjaAnalyzerConfig] = None
    ) -> BinaryNinjaAnalysis:
        if not config:
            async with resource.temp_to_disk(delete=False) as temp_path:
                bv = open_view(temp_path)
        else:
            bv = BinaryViewType.get_view_of_file(config.bndb_file)
            assert bv is not None

        return BinaryNinjaAnalysis(bv)

    def _create_dependencies(
        self,
        resource: Resource,
        resource_dependencies: Optional[List[ResourceAttributeDependency]] = None,
    ):
        """
        Override
        [Analyzer._create_dependencies][ofrak.component.component_analyzer.Analyzer._create_dependencies]
        to avoid the creation and tracking of dependencies between the BinaryNinja analysis,
        resource, and attributes.

        Practically speaking, this means that users of BinaryNinja components should group their
        work into three discrete, ordered steps:

        Step 1. Unpacking, Analysis
        Step 2. Modification
        Step 3. Packing
        """


class BinaryNinjaCustomLoadAnalyzer(
    Analyzer[Optional[BinaryNinjaAnalyzerConfig], BinaryNinjaAnalysis]
):
    """
    Opens and analyzes binaries with Binary Ninja for formats that Binary Ninja cannot
    auto-load. When MemoryRegion children are present, creates user segments at their
    specified virtual addresses with per-region permissions. Otherwise falls back to
    loading the entire binary as a flat blob with rebase support.
    """

    id = b"BinaryNinjaCustomLoadAnalyzer"
    targets = (BinaryNinjaCustomLoadProject,)
    outputs = (BinaryNinjaAnalysis,)

    async def analyze(
        self, resource: Resource, config: Optional[BinaryNinjaAnalyzerConfig] = None
    ) -> BinaryNinjaAnalysis:
        # Get ProgramAttributes early — used in both paths
        try:
            program_attrs = resource.get_attributes(ProgramAttributes)
        except NotFoundError:
            program_attrs = None

        # Check for MemoryRegion children (custom memory layout)
        regions = list(
            await resource.get_children_as_view(
                MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
            )
        )

        if regions and not config:
            bv = await self._load_with_regions(resource, regions, program_attrs)
        elif not config:
            bv = await self._load_flat(resource, program_attrs)
        else:
            bv = BinaryViewType.get_view_of_file(config.bndb_file)
            assert bv is not None

        return BinaryNinjaAnalysis(bv)

    async def _load_with_regions(
        self,
        resource: Resource,
        regions: List[MemoryRegion],
        program_attrs: Optional[ProgramAttributes],
    ) -> BinaryView:
        """Load binary with explicit MemoryRegion segments at their virtual addresses."""
        regions.sort(key=lambda r: r.virtual_address)

        # Build combined data buffer and per-region metadata
        combined_data = bytearray()
        segment_info = []  # (file_offset, vaddr, size, flags)
        for region in regions:
            perms = get_memory_region_permissions(region.resource)
            if perms is not None and perms.permissions == MemoryPermissions.NONE:
                continue
            region_data = await region.resource.get_data()
            file_offset = len(combined_data)
            flags = self._get_segment_flags(region, perms)
            segment_info.append((file_offset, region.virtual_address, region.size, flags))
            combined_data.extend(region_data)

        # Write combined data to temp file and open as raw binary.
        # delete=False because Binary Ninja retains an internal reference to the file
        # and may re-read it during analysis. This matches the pattern used elsewhere
        # in the Binary Ninja integration (e.g. temp_to_disk(delete=False)).
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(combined_data)
            temp_path = tmp.name

        bv = open_view(temp_path, update_analysis=False)

        # Remove auto-created segments and add user segments at correct vaddrs
        for seg in list(bv.segments):
            bv.remove_auto_segment(seg.start, seg.length)

        for file_offset, vaddr, size, flags in segment_info:
            bv.add_user_segment(vaddr, size, file_offset, size, flags)

        # Add entry points
        if program_attrs is not None and program_attrs.entry_points:
            for entry_addr in program_attrs.entry_points:
                bv.add_entry_point(entry_addr)
                LOGGER.info(f"Added entry point at 0x{entry_addr:x}")

        bv.update_analysis_and_wait()
        return bv

    async def _load_flat(
        self, resource: Resource, program_attrs: Optional[ProgramAttributes]
    ) -> BinaryView:
        """Load binary as a flat blob with optional rebase."""
        async with resource.temp_to_disk(delete=False) as temp_path:
            bv = open_view(temp_path, update_analysis=False)

        if program_attrs is not None:
            # Rebase FIRST if base_address differs from what Binary Ninja detected.
            # This must happen before adding entry points, since entry points are
            # specified as absolute addresses in the target address space.
            # Note: rebase() returns a NEW BinaryView; the original becomes invalid.
            if program_attrs.base_address is not None:
                current_base = bv.start
                if current_base != program_attrs.base_address:
                    new_bv = bv.rebase(program_attrs.base_address)
                    if new_bv is not None:
                        bv = new_bv
                        LOGGER.info(
                            f"Rebased from 0x{current_base:x} to "
                            f"0x{program_attrs.base_address:x}"
                        )
                    else:
                        raise RuntimeError(
                            f"Failed to rebase from 0x{current_base:x} to "
                            f"0x{program_attrs.base_address:x}"
                        )

            # Add entry points after rebasing (addresses are now correct)
            if program_attrs.entry_points:
                for entry_addr in program_attrs.entry_points:
                    bv.add_entry_point(entry_addr)
                    LOGGER.info(f"Added entry point at 0x{entry_addr:x}")

        bv.update_analysis_and_wait()
        return bv

    @staticmethod
    def _get_segment_flags(
        region: MemoryRegion, perms_attr: Optional[MemoryRegionPermissions] = None
    ) -> int:
        """Determine Binary Ninja SegmentFlags for a memory region."""
        if perms_attr is not None:
            perms = perms_attr.permissions
            flags = 0
            if perms.value & MemoryPermissions.R.value:
                flags |= SegmentFlag.SegmentReadable
            if perms.value & MemoryPermissions.W.value:
                flags |= SegmentFlag.SegmentWritable
            if perms.value & MemoryPermissions.X.value:
                flags |= SegmentFlag.SegmentExecutable
            return flags

        # Fall back: CodeRegion → RX, otherwise RW
        if region.resource.has_tag(CodeRegion):
            return SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
        return SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable

    def _create_dependencies(
        self,
        resource: Resource,
        resource_dependencies: Optional[List[ResourceAttributeDependency]] = None,
    ):
        """
        Override
        [Analyzer._create_dependencies][ofrak.component.component_analyzer.Analyzer._create_dependencies]
        to avoid the creation and tracking of dependencies between the BinaryNinja analysis,
        resource, and attributes.

        Practically speaking, this means that users of BinaryNinja components should group their
        work into three discrete, ordered steps:

        Step 1. Unpacking, Analysis
        Step 2. Modification
        Step 3. Packing
        """
