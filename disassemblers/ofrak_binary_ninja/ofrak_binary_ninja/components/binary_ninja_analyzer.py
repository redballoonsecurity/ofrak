import logging
import tempfile
from dataclasses import dataclass
from typing import Optional, List
from ofrak.component.abstract import ComponentMissingDependencyError

try:
    from binaryninja import open_view, BinaryViewType

    BINJA_INSTALLED = True
except ImportError:
    BINJA_INSTALLED = False

from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentConfig, ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributeDependency
from ofrak_binary_ninja.components.identifiers import BinaryNinjaAnalysisResource
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from ofrak.resource import Resource

LOGGER = logging.getLogger(__file__)


class _BinjaExternalTool(ComponentExternalTool):
    def __init__(self):
        super().__init__(
            "binary_ninja",
            "https://ofrak.com/docs/user-guide/disassembler-backends/binary_ninja.html",
            install_check_arg="",
        )

    async def is_tool_installed(self) -> bool:
        return BINJA_INSTALLED


BINJA_TOOL = _BinjaExternalTool()


@dataclass
class BinaryNinjaAnalyzerConfig(ComponentConfig):
    bndb_file: str  # Path to BinaryNinja DB pre-analyzed file


class BinaryNinjaAnalyzer(Analyzer[Optional[BinaryNinjaAnalyzerConfig], BinaryNinjaAnalysis]):
    id = b"BinaryNinjaAnalyzer"
    targets = (BinaryNinjaAnalysisResource,)
    outputs = (BinaryNinjaAnalysis,)
    external_dependencies = (BINJA_TOOL,)

    async def analyze(
        self, resource: Resource, config: Optional[BinaryNinjaAnalyzerConfig] = None
    ) -> BinaryNinjaAnalysis:
        if not BINJA_INSTALLED:
            raise ComponentMissingDependencyError(self, BINJA_TOOL)
        if not config:
            resource_data = await resource.get_data()
            temp_file = tempfile.NamedTemporaryFile()
            temp_file.write(resource_data)
            temp_file.flush()
            bv = open_view(temp_file.name)
            return BinaryNinjaAnalysis(bv)
        else:
            opt_bv = BinaryViewType.get_view_of_file(config.bndb_file)
            assert opt_bv is not None
            return BinaryNinjaAnalysis(opt_bv)

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
