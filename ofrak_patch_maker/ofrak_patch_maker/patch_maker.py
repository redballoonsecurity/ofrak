"""
`PatchMaker` - Create a Toolchain instance to build, allocate, and inject patches.

**Usage:**

```python
known_symbols = {"memcpy": 0xdeadbeef}
patch_maker = PatchMaker(
    program_attributes=attr,
    toolchain_config=tc_config,
    toolchain_version=tc_version,
    platform_includes="../usr/include",
    base_symbols=known_symbols
)

bom = patch_maker.make_bom(
    name="example",
    source_list=["./src/example.c", "./src/utils.c"],
    object_list=[],
    header_dirs=["./src/include"],
)

region_config = patch_maker.allocate_bom(
    Allocatable: allocatable,
    Resource: ofrak_fw_resource,
    BOM: bom
)

fem = patch_maker.make_fem([(bom, region_config)], ofrak_fw_resource, verbose=True)

patch_maker.inject_patch(verbose=True)
```
"""
import logging
import os
import tempfile
from collections import defaultdict
from types import ModuleType
from typing import Optional, List, Dict, Union, Tuple, Iterable, Mapping

from immutabledict import immutabledict

from ofrak.core.architecture import ProgramAttributes
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort, ResourceSortDirection
from ofrak.core.elf.model import Elf
from ofrak.core.free_space import (
    Allocatable,
)
from ofrak.core.injector import BinaryInjectorModifierConfig, BinaryInjectorModifier
from ofrak_patch_maker.model import (
    AssembledObject,
    BOM,
    FEM,
    PatchRegionConfig,
    LinkedExecutable,
    PatchMakerException,
)
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    Segment,
)
from ofrak_patch_maker.toolchain.version import ToolchainVersion
from ofrak_type.memory_permissions import MemoryPermissions


class PatchMaker:
    def __init__(
        self,
        program_attributes: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        toolchain_version: ToolchainVersion,
        platform_includes: Optional[Iterable[str]] = None,
        base_symbols: Mapping[str, int] = None,
        build_dir: str = ".",
        logger: logging.Logger = logging.getLogger(),
    ):
        """
        The PatchMaker class is responsible for building and applying FEM instance binary data
        to a client firmware substrate, whether they are micro patches or something larger.

        This entails:

        - Creating the toolchain-edited `.inc` files for both kernel symbols
        - Invoking the toolchain to compile and/or link one or a group of translation units,
          provided object files
        - Returning machine code, data, and info to the injection application about the
          patch artifacts (`readelf` style analysis, code carving, debug artifact generation)
        - Using information about the client firmware to translate virtual addresses to physical
          offsets

        The `PatchMaker` should never own any data. This more functional nature ensures the user
        should never be confused about the state of any [model.py][ofrak_patch_maker.model]
        primitives at any point between A and B over the course of a patch injection routine. In
        the future, this will provide more inherent threadsafety when non-OFRAK resource
        operations need to parallelized.

        We should not raise exceptions in protected APIs. Protected programming interfaces should
        not be used external to this class. Use outside of the class at your own risk.

        :param program_attributes: information about ISA/hardware
        :param toolchain_config: information that will be translated to various flags
        :param toolchain_version: used to derive the toolchain we'll be using
        :param platform_includes: Additional include directories
        :param base_symbols: maps symbol name to effective address for patches
        :param build_dir: output directory for build artifacts
        :param logger:
        """
        self._platform_includes = platform_includes
        self.build_dir = build_dir
        self._toolchain = self._get_toolchain(
            program_attributes, toolchain_config, toolchain_version, logger=logger
        )

        # String to file path of symbols.inc. This will be a build artifact.
        self._base_symbols: Dict[str, int] = {}
        self._base_symbol_file = None
        if base_symbols:
            _, filename = tempfile.mkstemp(
                dir=self.build_dir, prefix="base_symbols_", suffix=".inc"
            )
            self._base_symbol_file = self._toolchain.generate_linker_include_file(
                base_symbols, filename
            )
            self._base_symbols.update(base_symbols)

        self.logger = logger

    @staticmethod
    def _get_toolchain(
        program_attributes: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        toolchain_version: ToolchainVersion,
        logger: Union[logging.Logger, ModuleType] = logging,
    ) -> Toolchain:
        """
        :param program_attributes: information about ISA/hardware
        :param toolchain_config: information that will be translated to various flags
        :param toolchain_version: used to derive the toolchain we'll be using
        :param logger:

        :return: A Toolchain matching the given arguments
        """
        toolchain_cls = toolchain_version.value
        return toolchain_cls(
            processor=program_attributes, toolchain_config=toolchain_config, logger=logger
        )

    def _extract_symbols(self, path: str) -> Dict[str, int]:
        """
        :param path: path to a program or library binary with symbols

        :return: mapping symbol name to effective address
        """
        return self._toolchain.get_bin_file_symbols(path)

    @staticmethod
    def _is_executable_file(path: str) -> bool:
        return os.access(path, os.X_OK)

    def _prepare_executable(self, executable_path: str) -> LinkedExecutable:
        """
        :param executable_path:

        :return: an object containing path, symbol, and section information
        """
        symbols = self._extract_symbols(executable_path)
        segments = self._toolchain.get_bin_file_segments(executable_path)

        # TODO: Extract relocatable nature of the executable
        return LinkedExecutable(
            executable_path, self._toolchain.file_format, segments, symbols, relocatable=False
        )

    def prepare_object(self, object_path: str) -> AssembledObject:
        """
        This API is exposed to add existing (perhaps client-provided) `.o` files to a desired BOM.

        :param object_path:

        :raises PatchMakerException: if user provided input is invalid.
        :return: immutable, pre-analyzed `AssembledObject` containing section info
        """
        if os.path.isdir(object_path) or not os.path.exists(object_path):
            raise PatchMakerException("PatchMaker.prepare_object expects a valid object file path!")

        segments = self._toolchain.get_bin_file_segments(object_path)
        symbols = self._toolchain.get_bin_file_symbols(object_path)
        segment_map = {}
        for s in segments:
            segment_map[s.segment_name] = s
        return AssembledObject(
            object_path,
            self._toolchain.file_format,
            immutabledict(segment_map),
            immutabledict(symbols),
        )

    @staticmethod
    def _validate_bom_input(
        name: str,
        source_list: List[str],
        object_list: List[str],
        header_dirs: List[str],
    ):
        """
        :param name:
        :param source_list:
        :param object_list:
        :param header_dirs:

        :raises PatchMakerException: if user inputs are invalid.
        """
        if not isinstance(name, str) or not len(name) > 0:
            raise PatchMakerException("Invalid Patch name!")
        if len(source_list) == 0 and len(object_list) == 0:
            raise PatchMakerException("No source or objects provided!")
        valid_source_extensions = (".c", ".as", ".S")
        valid_object_extensions = ".o"
        bad_source = list(filter(lambda x: not x.endswith(valid_source_extensions), source_list))
        if len(bad_source) > 0:
            raise PatchMakerException(
                f"Source files must have .c, .as, or .S extension:\n {bad_source}"
            )
        bad_objects = list(filter(lambda x: not x.endswith(valid_object_extensions), object_list))
        if len(bad_objects) > 0:
            raise PatchMakerException(f"Object files must have a .o extension:\n {bad_objects}")
        paths = source_list + object_list + header_dirs
        bad_paths = list(filter(lambda x: not os.path.exists(x), paths))
        if len(bad_paths) > 0:
            raise PatchMakerException(f"Paths provided but not found:\n {bad_paths}")

    def make_bom(
        self,
        name: str,
        source_list: List[str],
        object_list: List[str],
        header_dirs: List[str],
        entry_point_name: Optional[str] = None,
    ) -> BOM:
        """
        The first API to call when generating a patch from source files.

        1. Collect the object files, analyze them, and wrap them as
           [AssembledObjects][ofrak_patch_maker.model.AssembledObject]
        2. Collect the `.c` source files, compile, and wrap them as
           [AssembledObjects][ofrak_patch_maker.model.AssembledObject]
        3. Collect the `.as`/`.S` files, preprocess if `.S`, assemble, and wrap them as
           [AssembledObjects][ofrak_patch_maker.model.AssembledObject]

        Note that wrapping as an [AssembledObject][ofrak_patch_maker.model.AssembledObject]
        implies that the size of each code segment (`.text`, `.data`, `.rodata`) has been recorded.

        :param name: BOM name
        :param source_list: list of `.c`, `.as`, `.S` files
        :param object_list: list of `.o` files
        :param header_dirs: list of directories with required `.h` files
        :param entry_point_name: program entry symbol, when relevant

        :raises PatchMakerException: if user inputs are invalid.
        :return: an immutable object containing section info
        """
        if self._platform_includes:
            header_dirs.extend(self._platform_includes)
        self._validate_bom_input(name, source_list, object_list, header_dirs)
        object_map = {}
        for o_file in object_list:
            assembled_object = self.prepare_object(o_file)
            object_map.update({o_file: assembled_object})

        out_dir = os.path.join(self.build_dir, name + "_bom_files")
        os.mkdir(out_dir)

        for c_file in list(filter(lambda x: x.endswith(".c"), source_list)):
            assembled_object_path = self._toolchain.compile(c_file, header_dirs, out_dir=out_dir)
            assembled_object = self.prepare_object(assembled_object_path)
            object_map.update({c_file: assembled_object})

        for asm_file in list(filter(lambda x: x.endswith(".as") or x.endswith(".S"), source_list)):
            original_asm_file = asm_file
            if asm_file.endswith(".S"):
                asm_file = self._toolchain.preprocess(asm_file, header_dirs, out_dir=out_dir)
            assembled_object_path = self._toolchain.assemble(asm_file, header_dirs, out_dir=out_dir)
            assembled_object = self.prepare_object(assembled_object_path)
            object_map.update({original_asm_file: assembled_object})

        # Compute the required size for the .bss segment
        bss_size_required = 0
        symbols: Dict[str, int] = {}
        for o in object_map.values():
            for segment_name in o.segment_map.keys():
                if not segment_name.startswith(".bss"):
                    continue
                bss_segment = o.segment_map[segment_name]
                if bss_segment.length == 0:
                    continue
                if self._toolchain._config.no_bss_section:
                    raise PatchMakerException(
                        f"{segment_name} found but `no_bss_section` is set in the provided ToolchainConfig!"
                    )
                bss_size_required += bss_segment.length
            symbols.update(o.symbols)

        if entry_point_name and entry_point_name not in symbols:
            raise PatchMakerException(f"Entry point {entry_point_name} not found in object files")

        return BOM(
            name,
            immutabledict(object_map),
            bss_size_required,
            entry_point_name,
        )

    def create_unsafe_bss_segment(self, vm_address: int, size: int) -> Segment:
        """
        The user may at times require the use of known unused `.bss` space.

        When this is required the data cannot be "properly", statically allocated, so an unsafe
        `.bss` section must be defined for where the data will be placed at runtime.

        :param vm_address: where the `.bss` section is expected to exist
        :param size: how large we expect the available `.bss` section to be

        :return: a [Segment][ofrak_patch_maker.toolchain.model.Segment] object.
        """
        segment = Segment(
            segment_name=".bss",
            vm_address=vm_address,
            offset=0x0,
            is_entry=False,
            length=size,
            access_perms=MemoryPermissions.RW,
        )
        align = self._toolchain.get_required_alignment(segment)
        if vm_address % align != 0:
            raise PatchMakerException(
                f"Provided address {hex(vm_address)} not aligned to required alignment: {hex(align)}"
            )
        return segment

    def _get_base_symbol_file(self) -> Optional[str]:
        if self._base_symbol_file:
            return self._base_symbol_file
        return None

    def _build_ld(
        self,
        boms: Iterable[Tuple[BOM, PatchRegionConfig]],
        bss_segment: Optional[Segment] = None,
        additional_symbols: Optional[Mapping[str, int]] = None,
    ) -> Optional[str]:
        """
        This routine is responsible for constructing the linker script by leveraging underlying
        toolchain methods. The linker will use this script to implement relocations and data
        placement as required for each of the BOMs' segments.

        It is also responsible for generating an additional symbols (`.inc`) file if more symbol
        mappings are provided.

        It would be better to pull this functionality into every concrete
        [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain] implementation than to make any
        architecture-specific choices here.

        :param boms: BOMs and their corresponding target memory descriptions
        :param bss_segment: A `.bss` segment, if any
        :param additional_symbols: Additional symbols to provide to this patch, if needed

        :return: path to `.ld` script file
        """
        memory_regions = []
        sections = []
        bss_size_required = 0
        name = next(iter(boms))[0].name  # peek at the first element for the name
        for bom, region_config in boms:
            for obj in bom.object_map.values():
                for segment in region_config.segments[obj.path]:
                    # Skip the segments we're not interested in.
                    # We have to create regions for 0-length segments to keep the linker happy!
                    if not self._toolchain.keep_section(segment.segment_name):
                        continue
                    memory_region, memory_region_name = self._toolchain.ld_generate_region(
                        obj.path,
                        segment.segment_name,
                        segment.access_perms,
                        segment.vm_address,
                        segment.length,
                    )
                    memory_regions.append(memory_region)
                    section = self._toolchain.ld_generate_section(
                        obj.path, segment.segment_name, memory_region_name
                    )
                    sections.append(section)

            if bom.bss_size_required > 0:
                if not bss_segment:
                    raise PatchMakerException(
                        f"BOM {bom.name} requires bss but no bss Segment allocation provided"
                    )
                bss_size_required += bom.bss_size_required

            if self._toolchain.is_relocatable():
                (
                    reloc_regions,
                    reloc_sections,
                ) = self._toolchain.ld_generate_placeholder_reloc_sections()
                memory_regions.extend(reloc_regions)
                sections.extend(reloc_sections)

        if bss_size_required > 0 and bss_segment is not None:
            if bss_size_required > bss_segment.length:
                raise PatchMakerException(
                    f"Not enough space in provided .bss segment!\n"
                    f"    Provided: {bss_segment.length} Required: {bss_size_required}"
                )
            bss_region, bss_name = self._toolchain.ld_generate_bss_region(
                bss_segment.vm_address, bss_segment.length
            )
            memory_regions.append(bss_region)
            bss_section = self._toolchain.ld_generate_bss_section(bss_name)
            sections.append(bss_section)

        base_symbol_file = self._get_base_symbol_file()
        symbol_files: List[str] = [base_symbol_file] if base_symbol_file is not None else []
        if additional_symbols:
            _, filename = tempfile.mkstemp(
                dir=self.build_dir, prefix="additional_symbols_", suffix=".inc"
            )
            additional_file = self._toolchain.generate_linker_include_file(
                additional_symbols, filename
            )
            symbol_files.append(additional_file)

        ld_script_path = self._toolchain.ld_script_create(
            name,
            memory_regions,
            sections,
            self.build_dir,
            symbol_files,
        )
        return ld_script_path

    def make_fem(
        self,
        boms: Iterable[Tuple[BOM, PatchRegionConfig]],
        exec_path: str,
        unsafe_bss_segment: Optional[Segment] = None,
        additional_symbols: Optional[Mapping[str, int]] = None,
    ) -> FEM:
        """
        This method validates user inputs, constructs a linker directive script (`.ld`), and drives
        the [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain] instance linker to create
        an executable file adhering to requirements specified in the
        [ToolchainConfig][ofrak_patch_maker.toolchain.model.ToolchainConfig].

        The resulting executable is compiled such that the code may be "carved" at its specified
        VM addresses and placed at the same VM address within another program.

        :param boms:
        :param exec_path:
        :param unsafe_bss_segment:
        :param additional_symbols:

        :raises PatchMakerException: for invalid user inputs
        :return: final executable patch and its section/symbol metadata
        """
        name = next(iter(boms))[0].name  # peek at the first element for the name
        o_paths = []
        for bom, region_config in boms:
            if not region_config:
                raise PatchMakerException("This API needs a valid PatchRegionConfig!")
            o_paths.extend([i.path for i in bom.object_map.values()])
        if not o_paths:
            raise PatchMakerException(
                f"No objects available in PatchBOM {name} to link an executable!"
            )

        ld_script_path = self._build_ld(
            boms,
            bss_segment=unsafe_bss_segment,
            additional_symbols=additional_symbols,
        )

        self._toolchain.link(o_paths, exec_path, script=ld_script_path)
        linked_executable = self._prepare_executable(exec_path)

        return FEM(name, linked_executable)

    async def _get_space(
        self,
        allocatable: Allocatable,
        perms: MemoryPermissions,
        required_size: int,
        alignment: int = 1,
    ) -> Tuple[int, int]:
        allocs = await allocatable.allocate(
            perms,
            required_size,
            min_fragment_size=required_size,
            alignment=alignment,
        )
        allocation = next(iter(allocs))
        return allocation.start, allocation.length()

    async def allocate_bom(
        self,
        allocatable: Allocatable,
        bom: BOM,
    ) -> PatchRegionConfig:
        """
        Responsible for allocating the patches if free memory is required and
        providing details about where space was made.

        Future, hopeful improvements include removing the `free_space_service` parameter once that
        functionality can be leveraged through
        [Resource][ofrak.resource.Resource].

        :param Allocatable allocatable:
        :param bom:

        :raises PatchMakerException: if the data service for `fw_resource` is in a bad state
        :return: information required to generate the linker directive script
        """
        segments_to_allocate: List[Tuple[AssembledObject, Segment]] = []
        for obj in bom.object_map.values():
            for segment in obj.segment_map.values():
                if not self._toolchain.keep_section(segment.segment_name):
                    continue
                segments_to_allocate.append((obj, segment))

        # Allocate largest segments first
        segments_to_allocate.sort(key=lambda o_s: o_s[1].length, reverse=True)
        segments_by_object: Dict[str, List[Segment]] = defaultdict(list)
        for obj, segment in segments_to_allocate:
            vaddr, final_size = 0, 0
            if segment.length > 0:
                vaddr, final_size = await self._get_space(
                    allocatable,
                    segment.access_perms,
                    segment.length,
                    alignment=self._toolchain.get_required_alignment(segment),
                )

            segments_by_object[obj.path].append(
                Segment(
                    segment_name=segment.segment_name,
                    vm_address=vaddr,
                    offset=segment.offset,
                    is_entry=segment.is_entry,
                    length=final_size,
                    access_perms=segment.access_perms,
                )
            )

        all_segments: Dict[str, Tuple[Segment, ...]] = {
            object_path: tuple(segments) for object_path, segments in segments_by_object.items()
        }

        return PatchRegionConfig(bom.name + "_patch", immutabledict(all_segments))

    async def inject_patch(
        self,
        patch_fem: FEM,
        resource: Resource,
        verbose: bool = False,
    ) -> Resource:
        """
        Leverages OFRAK's Injection Modifier to update the target
        firmware resource.

        :param patch_fem: final executable path and metadata about symbols, sections
        :param resource: OFRAK firmware resource
        :param verbose: prints patch section sizes and destinations at the effective logging level.
        """
        logger_level = self.logger.getEffectiveLevel() if verbose else logging.INFO
        program: Program = await resource.view_as(Program)

        with open(patch_fem.executable.path, "rb") as f:
            exe_data = f.read()
        sorted_regions = await program.resource.get_descendants_as_view(
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
        self.logger.log(logger_level, f"Injecting patch: {patch_fem.name}")
        for segment in patch_fem.executable.segments:
            if segment.length == 0 or segment.vm_address == 0:
                continue
            if segment.length > 0:
                self.logger.log(
                    logger_level,
                    f"    Segment {segment.segment_name} - {segment.length} "
                    f"bytes @ {hex(segment.vm_address)}",
                )
            if segment.segment_name.startswith(".bss"):
                continue
            segment_data = exe_data[segment.offset : segment.offset + segment.length]
            patches = [(segment.vm_address, segment_data)]
            region = MemoryRegion.get_mem_region_with_vaddr_from_sorted(
                segment.vm_address, sorted_regions
            )
            if region is None:
                raise ValueError(
                    f"Cannot inject patch because the memory region at vaddr "
                    f"{hex(segment.vm_address)} is None"
                )

            await region.resource.run(BinaryInjectorModifier, BinaryInjectorModifierConfig(patches))

        return resource

    @staticmethod
    def _orbytes(abytes, bbytes):
        return bytes(a | b for a, b in zip(abytes, bbytes))

    async def inject_null_base(self, patch_fem: FEM, resource: Resource, target: bytes) -> bytes:
        """
        This function injects the FEM patch into a `bytes` type base the same size as `resource`.

        Usecases for this debug result binary are emulation, static validation, test etc.

        :param patch_fem:
        :param resource:
        :param target:
        """
        elf = await resource.view_as(Elf)
        sections = await elf.get_sections()
        with open(patch_fem.executable.path, "rb") as f:
            exe_data = f.read()
        for segment in patch_fem.executable.segments:
            if segment.segment_name == ".bss":
                continue
            if segment.length == 0 or segment.vm_address == 0:
                continue
            segment_data = exe_data[segment.offset : segment.offset + segment.length]
            for s in sections:
                try:
                    offset = s.get_offset_in_self(segment.vm_address)
                    patch_first_half = b"\x00" * offset + segment_data
                    patch_second_half = b"\x00" * (s.size - len(patch_first_half))
                    patch = patch_first_half + patch_second_half
                    target = self._orbytes(target, patch)
                    self.logger.info(
                        f"Applying: {segment.segment_name} at offset: {hex(offset)} with "
                        f"virtual address: {hex(segment.vm_address)}"
                    )
                except AssertionError:
                    continue

        return target
