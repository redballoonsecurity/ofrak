import logging
from io import BytesIO
from dataclasses import dataclass, field
from typing import Any, List, Optional

from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributeDependency
from ofrak.resource import Resource

import angr.project
from ofrak_angr.components.identifiers import AngrAnalysisResource
from ofrak_angr.model import AngrAnalysis
from ofrak.component.modifier import Modifier
from ofrak.core import Program, CodeRegion
from ofrak import ResourceFilter


LOGGER = logging.getLogger(__file__)


@dataclass
class AngrAnalyzerConfig(ComponentConfig):
    cfg_analyzer: Any = angr.analyses.cfg.cfg_fast.CFGFast
    cfg_analyzer_args: dict = field(default_factory=lambda: {"normalize": True})

    project_args: dict = field(default_factory=lambda: {"auto_load_libs": False})

    post_cfg_analysis_hook: str = field(
        default='LOGGER.info(f"post_cfg_analysis_hooks: nothing to run")'
    )


class AngrAnalyzer(Analyzer[AngrAnalyzerConfig, AngrAnalysis]):
    id = b"AngrAnalyzer"
    targets = (AngrAnalysisResource,)
    outputs = (AngrAnalysis,)

    async def analyze(
        self, resource: Resource, config: AngrAnalyzerConfig = AngrAnalyzerConfig()
    ) -> AngrAnalysis:
        resource_data = await resource.get_data()

        project = angr.project.Project(BytesIO(resource_data), load_options=config.project_args)

        # Let's use angr to perform its own full analysis on the binary, and
        # maintain its results for the CR / CB / BB unpackers to re-use
        cfg = angr.analyses.analysis.AnalysisFactory(project, config.cfg_analyzer)(
            **config.cfg_analyzer_args
        )

        # Run any user-defined analysis here
        exec(config.post_cfg_analysis_hook)

        return AngrAnalysis(project)

    def _create_dependencies(
        self,
        resource: Resource,
        resource_dependencies: Optional[List[ResourceAttributeDependency]] = None,
    ):
        """
        Override
        [Analyzer._create_dependencies][ofrak.component.component_analyzer.Analyzer._create_dependencies]
        to avoid the creation and tracking of dependencies between the angr analysis,
        resource, and attributes.

        Practically speaking, this means that users of angr components should group their
        work into three discrete, ordered steps:

        Step 1. Unpacking, Analysis
        Step 2. Modification
        Step 3. Packing
        """


@dataclass
class AngrCodeRegionModifierConfig(ComponentConfig):
    angr_analysis: AngrAnalysis


class AngrCodeRegionModifier(Modifier):
    id = b"AngrCodeRegionModifier"
    targets = (CodeRegion,)

    async def modify(self, resource: Resource, config: Optional[AngrCodeRegionModifierConfig]):
        code_region  = await resource.view_as(CodeRegion)
        obj = config.angr_analysis.project.loader.main_object

        program = await resource.get_only_ancestor_as_view(
            Program, r_filter=ResourceFilter(tags=[Program])
        )

        ofrak_code_regions = await program.resource.get_descendants_as_view(
            CodeRegion, r_filter=ResourceFilter(tags=[CodeRegion])
        )
        backend_code_regions = [CodeRegion(s.vaddr, s.memsize) for s in obj.segments]

        ofrak_code_regions = sorted(ofrak_code_regions, key=lambda cr: cr.virtual_address)
        backend_code_regions = sorted(backend_code_regions, key=lambda cr: cr.virtual_address)

        if len(ofrak_code_regions) > 0:
            relative_va = code_region.virtual_address - ofrak_code_regions[0].virtual_address

            for backend_cr in backend_code_regions:
                backend_relative_va = (
                    backend_cr.virtual_address - backend_code_regions[0].virtual_address
                )

                if backend_relative_va == relative_va and backend_cr.size == code_region.size:
                    resource.add_view(backend_cr)
                    return

            LOGGER.debug(
                f"No code region with relative offset {relative_va} and size {code_region.size} found in Angr"
            )
        else:
            LOGGER.debug("No OFRAK code regions to match in Angr")

