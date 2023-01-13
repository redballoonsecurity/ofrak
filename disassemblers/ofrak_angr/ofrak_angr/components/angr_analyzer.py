import logging
from io import BytesIO
from dataclasses import dataclass, field
from typing import Any, List, Optional

from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributeDependency
from ofrak.resource import Resource

import angr.project
from ofrak.core.elf.model import Elf, ElfHeader, ElfType
from ofrak_angr.components.identifiers import AngrAnalysisResource
from ofrak_angr.model import AngrAnalysis
from ofrak.component.modifier import Modifier
from ofrak.core import CodeRegion
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


class AngrCodeRegionModifier(Modifier):
    id = b"AngrCodeRegionModifier"
    targets = (CodeRegion,)

    async def modify(self, resource: Resource, config=None):
        code_region = await resource.view_as(CodeRegion)

        root_resource = await resource.get_only_ancestor(
            ResourceFilter(tags=[AngrAnalysisResource], include_self=True)
        )

        fixup_address = False

        # We only want to adjust the address of a CodeRegion if the original binary is position-independent.
        # Implement PIE-detection for other file types as necessary.
        if root_resource.has_tag(Elf):
            elf_header = await root_resource.get_only_descendant_as_view(
                ElfHeader, r_filter=ResourceFilter(tags=[ElfHeader])
            )

            if elf_header is not None and elf_header.e_type == ElfType.ET_DYN.value:
                fixup_address = True
        else:
            LOGGER.warning(
                f"Have not implemented PIE-detection for {root_resource}. The address of {code_region} will likely be incorrect."
            )

        if fixup_address:
            angr_analysis = await root_resource.analyze(AngrAnalysis)
            obj = angr_analysis.project.loader.main_object

            if obj is not None:
                new_cr = CodeRegion(code_region.virtual_address + obj.min_addr, code_region.size)
                code_region.resource.add_view(new_cr)
            else:
                LOGGER.warning(
                    f"There is no angr main object for resource {root_resource}. Something went wrong."
                )
