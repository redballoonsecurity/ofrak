import logging
from io import BytesIO
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource

import archinfo
import angr.project
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.elf.model import Elf, ElfHeader, ElfType
from ofrak.core.memory_region import (
    MemoryRegion,
    get_effective_memory_permissions,
    get_memory_region_permissions,
)
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
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


def _run_angr_analysis(
    load_data: BytesIO, project_args: dict, config: AngrAnalyzerConfig
) -> AngrAnalysis:
    """
    Create an angr project, run CFG analysis, and execute post-analysis hook.
    """
    project = angr.project.Project(load_data, load_options=project_args)
    cfg = angr.analyses.analysis.AnalysisFactory(project, config.cfg_analyzer)(
        **config.cfg_analyzer_args
    )
    exec(config.post_cfg_analysis_hook)
    return AngrAnalysis(project)


_ANGR_ARCH_MAP = {
    (InstructionSet.X86, BitWidth.BIT_32): "X86",
    (InstructionSet.X86, BitWidth.BIT_64): "AMD64",
    (InstructionSet.ARM, BitWidth.BIT_32): "ARMEL",
    (InstructionSet.AARCH64, BitWidth.BIT_64): "AARCH64",
    (InstructionSet.MIPS, BitWidth.BIT_32): "MIPS32",
    (InstructionSet.MIPS, BitWidth.BIT_64): "MIPS64",
    (InstructionSet.PPC, BitWidth.BIT_32): "PPC32",
    (InstructionSet.PPC, BitWidth.BIT_64): "PPC64",
    (InstructionSet.AVR, BitWidth.BIT_16): "AVR8",
    (InstructionSet.SPARC, BitWidth.BIT_32): "SPARC32",
    (InstructionSet.SPARC, BitWidth.BIT_64): "SPARC64",
}

_ENDIANNESS_TO_ARCHINFO = {
    Endianness.BIG_ENDIAN: archinfo.Endness.BE,
    Endianness.LITTLE_ENDIAN: archinfo.Endness.LE,
}


def _resolve_angr_arch(
    program_attrs: ProgramAttributes,
) -> Optional[archinfo.Arch]:
    """
    Resolve ProgramAttributes to an archinfo.Arch with correct endianness.
    """
    arch_name = _ANGR_ARCH_MAP.get((program_attrs.isa, program_attrs.bit_width))
    if arch_name is None:
        return None
    endness = _ENDIANNESS_TO_ARCHINFO.get(program_attrs.endianness)
    try:
        return archinfo.arch_from_id(arch_name, endness=endness)
    except archinfo.ArchNotFound:
        raise NotFoundError(
            f"angr does not support architecture {program_attrs.isa.name} "
            f"{program_attrs.bit_width.value}-bit {program_attrs.endianness.name}"
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
        return _run_angr_analysis(BytesIO(resource_data), config.project_args, config)


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
        main_opts: dict = {}
        try:
            program_attrs = resource.get_attributes(ProgramAttributes)
        except NotFoundError:
            program_attrs = None

        if program_attrs is not None:
            if program_attrs.entry_points:
                # angr's CLE loader only accepts a single entry_point; additional
                # entry points are typically discovered by CFGFast's heuristics.
                main_opts["entry_point"] = program_attrs.entry_points[0]
            if program_attrs.base_address is not None:
                main_opts["base_addr"] = program_attrs.base_address
            angr_arch = _resolve_angr_arch(program_attrs)
            if angr_arch is not None:
                main_opts["arch"] = angr_arch

        regions = list(
            await resource.get_children_as_view(
                MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
            )
        )

        if regions:
            regions.sort(key=lambda r: r.virtual_address)
            combined_data = bytearray()
            segments = []
            code_regions: List[Tuple[int, int]] = []
            for region in regions:
                perms = get_memory_region_permissions(region.resource)
                if perms is not None and perms.permissions == MemoryPermissions.NONE:
                    continue
                region_data = await region.resource.get_data()
                file_offset = len(combined_data)
                vaddr = region.virtual_address
                size = region.size
                segments.append((file_offset, vaddr, len(region_data)))
                combined_data.extend(region_data)

                effective = get_effective_memory_permissions(region.resource)
                if effective.value & MemoryPermissions.X.value:
                    code_regions.append((vaddr, vaddr + size))

            if not segments:
                raise ValueError("No accessible memory regions for analysis")

            if not code_regions:
                raise ValueError("No executable memory regions for analysis")

            main_opts["backend"] = "blob"
            main_opts["segments"] = segments
            if "base_addr" not in main_opts:
                main_opts["base_addr"] = segments[0][1]

            load_data = BytesIO(bytes(combined_data))
        else:
            code_regions = []
            load_data = BytesIO(await resource.get_data())

        # User-supplied main_opts take priority over ProgramAttributes values
        project_args = dict(config.project_args)
        if main_opts:
            project_args["main_opts"] = {**main_opts, **project_args.get("main_opts", {})}

        # Restrict CFGFast to executable regions to avoid scanning sparse gaps
        if code_regions and "regions" not in config.cfg_analyzer_args:
            cfg_args = dict(config.cfg_analyzer_args)
            cfg_args["regions"] = code_regions
            config = AngrAnalyzerConfig(
                cfg_analyzer=config.cfg_analyzer,
                cfg_analyzer_args=cfg_args,
                project_args=config.project_args,
                post_cfg_analysis_hook=config.post_cfg_analysis_hook,
            )

        return _run_angr_analysis(load_data, project_args, config)


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
