import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Type, Union, cast, Any

from ofrak.core import ProgramAttributes
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak.component.modifier import Modifier
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort, ResourceSortDirection
from ofrak.core.injector import BinaryInjectorModifier, BinaryInjectorModifierConfig
from ofrak_patch_maker.model import PatchRegionConfig, FEM
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import Segment, ToolchainConfig
from ofrak_type.memory_permissions import MemoryPermissions

LOGGER = logging.getLogger(__file__)

SourceDirType = Dict[str, Union[str, Any]]  # Recursive types not supported by this version of mypy


@dataclass
class PatchFromSourceModifierConfig(ComponentConfig):
    """
    :var source_code: Path to directory containing source code
    :var source_patches: path of each source file to build and inject, with one or more segments
    defining where to inject one or more of the .text, .data, and .rodata from the build file
    :var toolchain_config: configuration for the
    [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain] to use
    :var toolchain: the type of which [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain]
      to use to build patch
    :var patch_name: Optional name of patch
    :var header_directories: (Optional) paths to directories to search for header files in
    """

    source_code_slurped: SourceDirType
    source_patches: Dict[str, Tuple[Segment, ...]]
    toolchain_config: ToolchainConfig
    toolchain: Type[Toolchain]
    header_directories_slurped: Tuple[SourceDirType, ...]
    patch_name: Optional[str] = None

    @classmethod
    def from_directories(
        cls,
        source_code: str,
        source_patches: Dict[str, Tuple[Segment, ...]],
        toolchain_config: ToolchainConfig,
        toolchain: Type[Toolchain],
        patch_name: Optional[str] = None,
        header_directories: Tuple[str, ...] = (),
    ) -> "PatchFromSourceModifierConfig":
        source_code_slurped = PatchFromSourceModifierConfig.slurp_source_directory(source_code)
        header_directories_slurped = tuple(
            PatchFromSourceModifierConfig.slurp_source_directory(header_dir)
            for header_dir in header_directories
        )
        return PatchFromSourceModifierConfig(
            source_code_slurped,
            source_patches,
            toolchain_config,
            toolchain,
            header_directories_slurped,
            patch_name,
        )

    @staticmethod
    def slurp_source_directory(path: str) -> SourceDirType:
        res: SourceDirType = {}
        root, dirs, files = next(os.walk(path, topdown=True))
        for file_name in files:
            file_path = os.path.join(root, file_name)
            with open(file_path) as f:
                file_contents = f.read()

            res[file_name] = file_contents

        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            res[dir_name] = PatchFromSourceModifierConfig.slurp_source_directory(dir_path)

        return res

    @staticmethod
    def dump_source_directory(target_path: str, sources: SourceDirType):
        os.makedirs(target_path, exist_ok=True)
        for item_name, item_contents in sources.items():
            item_path = os.path.join(target_path, item_name)
            if type(item_contents) is str:
                # item is a file
                with open(item_path, "w") as f:
                    f.write(item_contents)
            else:
                # item is a directory
                PatchFromSourceModifierConfig.dump_source_directory(
                    item_path, cast(SourceDirType, item_contents)
                )


class PatchFromSourceModifier(Modifier):
    """
    Modifier exposing some basic source code patching capabilities.
    """

    targets = (Program,)

    async def modify(self, resource: Resource, config: PatchFromSourceModifierConfig) -> None:

        if config.patch_name is None:
            patch_name = f"{resource.get_id().hex()}_patch_{os.path.basename(config.source_code)}"
        else:
            patch_name = config.patch_name

        build_tmp_dir = tempfile.mkdtemp()

        source_tmp_dir = tempfile.mkdtemp()
        PatchFromSourceModifierConfig.dump_source_directory(
            source_tmp_dir, config.source_code_slurped
        )

        header_dirs = []
        for header_directory in config.header_directories_slurped:
            header_tmp_dir = tempfile.mkdtemp()
            PatchFromSourceModifierConfig.dump_source_directory(header_tmp_dir, header_directory)
            header_dirs.append(header_tmp_dir)

        absolute_source_list = [
            os.path.join(source_tmp_dir, src_file) for src_file in config.source_patches.keys()
        ]
        program_attributes = await resource.analyze(ProgramAttributes)
        patch_maker = PatchMaker(
            toolchain=config.toolchain(program_attributes, config.toolchain_config),
            build_dir=build_tmp_dir,
        )

        patch_bom = patch_maker.make_bom(
            name=patch_name,
            source_list=absolute_source_list,
            object_list=[],
            header_dirs=header_dirs,
        )

        # Map each object file in the BOM to the segments associated with its source file
        patch_bom_segment_mapping = {
            patch_bom.object_map[os.path.join(source_tmp_dir, src_file)].path: src_segments
            for src_file, src_segments in config.source_patches.items()
        }

        target_program = await resource.view_as(Program)
        target_linkable_bom_info = await target_program.make_linkable_bom(
            patch_maker,
            build_tmp_dir,
        )
        # To support additional dynamic references in user space executables
        # Create and use a modifier that will:
        # 1. Extend .got, add new entry
        # 2. Extend .got.plt, add new stub code
        # 3. If the DSO is not already listed in the load list for executable it must be extended and added.
        # 4. Provide the additional .got and .got.plt symbols to make_fem now that we have the locations
        # NOTE: These external functions will probably be UND*
        p = PatchRegionConfig(patch_bom.name + "_patch", patch_bom_segment_mapping)
        exec_path = os.path.join(build_tmp_dir, "output_exec")
        fem = patch_maker.make_fem([(patch_bom, p), target_linkable_bom_info], exec_path)

        await resource.run(
            SegmentInjectorModifier,
            SegmentInjectorModifierConfig.from_fem(fem),
        )


@dataclass
class SegmentInjectorModifierConfig(ComponentConfig):
    segments_and_data: Tuple[Tuple[Segment, bytes], ...]

    @staticmethod
    def from_fem(fem: FEM) -> "SegmentInjectorModifierConfig":
        """
        Automatically build a config from a FEM by extracting each segment's bytes and metadata.
        """
        extracted_segments: List[Tuple[Segment, bytes]] = []
        with open(fem.executable.path, "rb") as f:
            exe_data = f.read()
        for segment in fem.executable.segments:
            if segment.length == 0:
                continue
            segment_data = exe_data[segment.offset : segment.offset + segment.length]
            extracted_segments.append((segment, segment_data))
        return SegmentInjectorModifierConfig(tuple(extracted_segments))


class SegmentInjectorModifier(Modifier[SegmentInjectorModifierConfig]):
    """
    Inject some segments into a Program resource. Only segments with non-zero length are
    injected, excluding .bss.
    """

    targets = (Program,)

    async def modify(self, resource: Resource, config: SegmentInjectorModifierConfig) -> None:
        sorted_regions = list(
            await resource.get_descendants_as_view(
                MemoryRegion,
                r_filter=ResourceFilter(
                    include_self=True,
                    tags=(MemoryRegion,),
                ),
                r_sort=ResourceSort(
                    attribute=MemoryRegion.Size,
                    direction=ResourceSortDirection.DESCENDANT,
                ),
            )
        )

        injection_tasks: List[Tuple[Resource, BinaryInjectorModifierConfig]] = []

        for segment, segment_data in config.segments_and_data:
            if segment.length == 0 or segment.vm_address == 0:
                continue
            if segment.length > 0:
                LOGGER.debug(
                    f"    Segment {segment.segment_name} - {segment.length} "
                    f"bytes @ {hex(segment.vm_address)}",
                )
            if segment.segment_name.startswith(".bss"):
                continue
            if segment.segment_name.startswith(".rela"):
                continue
            if segment.segment_name.startswith(".got"):
                # Create new .got and .plt in the exec format here here once we begin supporting
                # the addition of new dynamic references in our patches.
                # For instance, a new call to kmalloc that never existed before.
                # See PatchFromSourceModifier
                continue

            patches = [(segment.vm_address, segment_data)]
            region = MemoryRegion.get_mem_region_with_vaddr_from_sorted(
                segment.vm_address, sorted_regions
            )
            if region is None:
                raise ValueError(
                    f"Cannot inject patch because the memory region at vaddr "
                    f"{hex(segment.vm_address)} is None"
                )

            injection_tasks.append((region.resource, BinaryInjectorModifierConfig(patches)))

        for injected_resource, injection_config in injection_tasks:
            result = await injected_resource.run(BinaryInjectorModifier, injection_config)
            # The above can patch data of any of injected_resources' descendants or ancestors
            # We don't want to delete injected_resources or its ancestors, so subtract them from the
            # set of patched resources
            patched_descendants = result.resources_modified.difference(
                {
                    r.get_id()
                    for r in await injected_resource.get_ancestors(
                        ResourceFilter(include_self=True)
                    )
                }
            )
            to_delete = [
                r for r in await resource.get_descendants() if r.get_id() in patched_descendants
            ]
            await asyncio.gather(*(r.delete() for r in to_delete))


@dataclass
class FunctionReplacementModifierConfig(ComponentConfig):
    """
    :var source_code: Path to directory containing source code
    :var new_function_sources: a mapping from function names (to replace) to source code file paths (to use as
    replacements). The paths are relative paths within the source code FilesystemRoot.
    :var toolchain_config: configuration for the
    [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain] to use
    :var toolchain: the type of which type of [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain] to use
    :var patch_name: Optional name of patch
    :var header_directories: (Optional) paths to directories to search for header files in
    """

    source_code: str
    new_function_sources: Dict[str, str]
    toolchain_config: ToolchainConfig
    toolchain: Type[Toolchain]
    patch_name: Optional[str] = None
    header_directories: Tuple[str, ...] = ()

    # Populated by post init, slurping up source and header directories "client-side"
    source_code_slurped: SourceDirType = field(init=False, repr=False)
    header_directories_slurped: Tuple[SourceDirType, ...] = field(init=False, repr=False)

    def __post_init__(self):
        self.source_code_slurped = PatchFromSourceModifierConfig.slurp_source_directory(
            self.source_code
        )
        self.header_directories_slurped = tuple(
            PatchFromSourceModifierConfig.slurp_source_directory(header_dir)
            for header_dir in self.header_directories
        )


class FunctionReplacementModifier(Modifier[FunctionReplacementModifierConfig]):
    """
    Replace one or several functions in a `Program` resource.

    It takes a mapping from function names (to replace) to source code file paths (to use as replacements), then
    for each function to replace, creates a `Segment` from the corresponding complex block and uses the
    `PatchFromSourceModifier` to overwrite this segment with the code taken from the replacement source code file.
    """

    targets = (Program,)

    async def modify(self, resource: Resource, config: FunctionReplacementModifierConfig) -> None:
        program = await resource.view_as(Program)
        function_to_replace_cbs = {
            func_name: await program.get_function_complex_block(func_name)
            for func_name in config.new_function_sources.keys()
        }
        await self._verify_modes_are_the_same(list(function_to_replace_cbs.values()))
        source_patches: Dict[str, Tuple[Segment, ...]] = {
            config.new_function_sources[func_name]: (self._make_text_segment(complex_block),)
            for func_name, complex_block in function_to_replace_cbs.items()
        }
        patch_from_source_config = PatchFromSourceModifierConfig(
            "",
            source_patches,
            config.toolchain_config,
            config.toolchain,
            config.patch_name,
            (),
        )
        patch_from_source_config.source_code = config.source_code
        patch_from_source_config.source_code_slurped = config.source_code_slurped
        patch_from_source_config.header_directories = config.header_directories
        patch_from_source_config.header_directories_slurped = config.header_directories_slurped
        await resource.run(PatchFromSourceModifier, patch_from_source_config)

    @staticmethod
    def _make_text_segment(complex_block: ComplexBlock) -> Segment:
        """Return a new code `Segment` corresponding to `complex_block`."""
        return Segment(
            segment_name=".text",
            vm_address=complex_block.virtual_address,
            offset=0,
            is_entry=False,
            length=complex_block.size,
            access_perms=MemoryPermissions.RX,
        )

    @staticmethod
    async def _verify_modes_are_the_same(complex_blocks: List[ComplexBlock]) -> None:
        """
        Verify that the `InstructionSetMode` of all the `complex_blocks` is the same.

        :raises NotImplementedError: if several `InstructionSetMode` values are found
        """
        modes = {await complex_block.get_mode() for complex_block in complex_blocks}
        if len(modes) > 1:
            raise NotImplementedError(
                f"Several values of InstructionSetMode found in complex blocks {complex_blocks}: {modes}\n"
                "This is not currently supported by this component: all complex blocks must have the same mode "
                "in order to be processed in the same patch."
            )
