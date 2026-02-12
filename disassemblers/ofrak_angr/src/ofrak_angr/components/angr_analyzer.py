import logging
from io import BytesIO
from dataclasses import dataclass, field
from typing import Any, List, Optional

from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributeDependency
from ofrak.resource import Resource

import angr.project
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.elf.model import Elf, ElfHeader, ElfType
from ofrak.core.memory_region import MemoryRegion, MemoryRegionPermissions
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_angr.model import (
    AngrAnalysis,
    AngrAnalysisResource,
    AngrAutoLoadProject,
    AngrCustomLoadProject,
)
from ofrak.component.modifier import Modifier
from ofrak.core import CodeRegion
from ofrak import ResourceFilter
from ofrak_type.error import NotFoundError


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
    """
    Runs angr's automated binary analysis engine to build control flow graphs (CFG), identify
    functions, and analyze program structure. Use for auto-loadable formats (ELF, PE, Ihex) where
    angr can automatically determine the binary format. Creates AngrAnalysis state for other angr
    components to use.
    """

    id = b"AngrAnalyzer"
    targets = (AngrAutoLoadProject,)
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


class AngrCustomLoadAnalyzer(Analyzer[AngrAnalyzerConfig, AngrAnalysis]):
    """
    Runs angr analysis on binaries that angr cannot auto-load (raw blobs, custom formats).
    Consumes entry_points and base_address from ProgramAttributes to configure angr's loader.
    Use for custom loading scenarios where the binary format is not natively supported by angr.
    """

    id = b"AngrCustomLoadAnalyzer"
    targets = (AngrCustomLoadProject,)
    outputs = (AngrAnalysis,)

    async def analyze(
        self, resource: Resource, config: AngrAnalyzerConfig = AngrAnalyzerConfig()
    ) -> AngrAnalysis:
        # Get entry point and base address from ProgramAttributes
        main_opts: dict = {}
        try:
            program_attrs = resource.get_attributes(ProgramAttributes)
            if program_attrs.entry_points:
                main_opts["entry_point"] = program_attrs.entry_points[0]
            if program_attrs.base_address is not None:
                main_opts["base_addr"] = program_attrs.base_address
        except NotFoundError:
            program_attrs = None

        # Check for MemoryRegion children (custom memory layout)
        regions = list(
            await resource.get_children_as_view(
                MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
            )
        )

        if regions:
            # Sort by virtual address for deterministic layout
            regions.sort(key=lambda r: r.virtual_address)

            # Build combined data buffer and segment list for angr's blob backend.
            # Each segment is (file_offset, vaddr, size).
            combined_data = bytearray()
            segments = []
            for region in regions:
                # Skip regions with NONE permissions (guard pages, reserved address space)
                try:
                    perms_attr = region.resource.get_attributes(MemoryRegionPermissions)
                    if perms_attr.permissions == MemoryPermissions.NONE:
                        continue
                except NotFoundError:
                    pass
                region_data = await region.resource.get_data()
                file_offset = len(combined_data)
                segments.append((file_offset, region.virtual_address, region.size))
                combined_data.extend(region_data)

            main_opts["backend"] = "blob"
            main_opts["segments"] = segments
            if "base_addr" not in main_opts:
                main_opts["base_addr"] = regions[0].virtual_address

            load_data = BytesIO(bytes(combined_data))
        else:
            load_data = BytesIO(await resource.get_data())

        # Merge main_opts into project_args (copy to avoid mutating config).
        # User-supplied main_opts take priority over ProgramAttributes values.
        project_args = dict(config.project_args)
        if main_opts:
            project_args["main_opts"] = {**main_opts, **project_args.get("main_opts", {})}

        project = angr.project.Project(load_data, load_options=project_args)

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
    """
    Adjusts CodeRegion virtual addresses to account for position-independent executables (PIE) using angr's loader.
    Automatically detects PIE binaries (currently supports ELF) and fixes addresses relative to angr's base address.
    Used internally by angr unpacking workflow.

    For more details on the PIE fixups, see [gotchas.md](docs/user-guide/disassembler-backends/gotchas.md).
    """

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
