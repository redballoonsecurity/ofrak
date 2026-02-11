import logging
from dataclasses import dataclass
from typing import Optional, List

from binaryninja import open_view, BinaryViewType

from ofrak.component.analyzer import Analyzer
from ofrak.core.architecture import ProgramAttributes
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributeDependency
from ofrak_binary_ninja.components.identifiers import BinaryNinjaAnalysisResource
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from ofrak.resource import Resource
from ofrak_type.error import NotFoundError

LOGGER = logging.getLogger(__file__)


@dataclass
class BinaryNinjaAnalyzerConfig(ComponentConfig):
    bndb_file: str  # Path to BinaryNinja DB pre-analyzed file


class BinaryNinjaAnalyzer(Analyzer[Optional[BinaryNinjaAnalyzerConfig], BinaryNinjaAnalysis]):
    """
    Opens and analyzes binaries with Binary Ninja, either from scratch or from a pre-analyzed BNDB file. Creates
    BinaryNinjaAnalysis state containing the BinaryView for use by other Binary Ninja components. Use for initial
    comprehensive analysis with Binary Ninja's powerful analysis engine.
    """

    id = b"BinaryNinjaAnalyzer"
    targets = (BinaryNinjaAnalysisResource,)
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

        # Try to get entry points and base address from ProgramAttributes
        try:
            program_attrs = resource.get_attributes(ProgramAttributes)

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
                        LOGGER.warning(
                            f"Failed to rebase from 0x{current_base:x} to "
                            f"0x{program_attrs.base_address:x}"
                        )

            # Add entry points after rebasing (addresses are now correct)
            if program_attrs.entry_points:
                for entry_addr in program_attrs.entry_points:
                    bv.add_entry_point(entry_addr)
                    LOGGER.info(f"Added entry point at 0x{entry_addr:x}")
        except NotFoundError:
            pass

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
