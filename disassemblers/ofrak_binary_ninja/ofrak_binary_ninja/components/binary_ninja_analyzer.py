import logging
from dataclasses import dataclass
from typing import Optional, List

from binaryninja import open_view, BinaryViewType

from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributeDependency
from ofrak_binary_ninja.components.identifiers import BinaryNinjaAnalysisResource
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from ofrak.resource import Resource

LOGGER = logging.getLogger(__file__)


@dataclass
class BinaryNinjaAnalyzerConfig(ComponentConfig):
    bndb_file: str  # Path to BinaryNinja DB pre-analyzed file


class BinaryNinjaAnalyzer(Analyzer[Optional[BinaryNinjaAnalyzerConfig], BinaryNinjaAnalysis]):
    id = b"BinaryNinjaAnalyzer"
    targets = (BinaryNinjaAnalysisResource,)
    outputs = (BinaryNinjaAnalysis,)

    async def analyze(
        self, resource: Resource, config: Optional[BinaryNinjaAnalyzerConfig] = None
    ) -> BinaryNinjaAnalysis:
        if not config:
            async with resource.temp_to_disk(delete=False) as temp_path:
                bv = open_view(temp_path)

            return BinaryNinjaAnalysis(bv)
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
