"""
`PatchMaker` - Create a Toolchain instance to build, allocate, and inject patches.

**Usage:**

```python
tc = GNU_ARM_NONE_EABI_10_2_1_Toolchain(...). # Instantiate the toolchain you want to use.
known_symbols = {"memcpy": 0xdeadbeef}
patch_maker = PatchMaker(
    toolchain=tc
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

await ofrak_fw_resource.run(SegmentInjectorModifier, SegmentInjectorModifierConfig.from_fem(fem))
```
"""
import logging
import itertools
import os
import tempfile
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple
from warnings import warn

from immutabledict import immutabledict

from ofrak_patch_maker.model import (
    AssembledObject,
    BOM,
    FEM,
    PatchRegionConfig,
    LinkedExecutable,
    PatchMakerException,
    SourceFileType,
)
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.model import (
    Segment,
)
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.symbol_type import LinkableSymbolType


class PatchMaker:
    def __init__(
        self,
        toolchain: Toolchain,
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

        :param toolchain: a Toolchain instance with compile, link, assemble, etc. methods
        :param platform_includes: Additional include directories
        :param base_symbols: maps symbol name to effective address for patches
        :param build_dir: output directory for build artifacts
        :param logger:
        """
        self._platform_includes = platform_includes
        self.build_dir = build_dir
        self._toolchain = toolchain

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

    def _extract_symbols(self, path: str) -> Dict[str, Tuple[int, LinkableSymbolType]]:
        """
        :param path: path to a program or library binary with symbols

        :return: mapping symbol name to effective address
        """
        return self._toolchain.get_bin_file_symbols(path)

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
        # Symbols defined in another file which may or may not be another patch source file or the target binary.
        relocation_symbols = self._toolchain.get_bin_file_rel_symbols(object_path)

        bss_size_required = 0
        segment_map = {}
        for s in segments:
            if self._toolchain.keep_section(s.segment_name):
                segment_map[s.segment_name] = s
            if s.segment_name.startswith(".bss"):
                if s.length > 0 and self._toolchain._config.no_bss_section:
                    raise PatchMakerException(
                        f"{s.segment_name} found but `no_bss_section` is set in the provided ToolchainConfig!"
                    )
                bss_size_required += s.length
        return AssembledObject(
            object_path,
            self._toolchain.file_format,
            immutabledict(segment_map),
            immutabledict(symbols),
            immutabledict(relocation_symbols),
            bss_size_required,
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

        c_files = list(filter(lambda x: x.endswith(".c"), source_list))
        c_args = zip(
            c_files,
            itertools.repeat(header_dirs),
            itertools.repeat(out_dir),
            itertools.repeat(SourceFileType.C),
        )
        result = itertools.starmap(self._create_object_file, c_args)
        for r in result:
            object_map.update(r)

        asm_files = list(filter(lambda x: x.endswith(".as") or x.endswith(".S"), source_list))
        asm_args = zip(
            asm_files,
            itertools.repeat(header_dirs),
            itertools.repeat(out_dir),
            itertools.repeat(SourceFileType.ASM),
        )
        result = itertools.starmap(self._create_object_file, asm_args)
        for r in result:
            object_map.update(r)

        # Compute the required size for the .bss segment
        bss_size_required, unresolved_sym_set = self._resolve_symbols_within_BOM(
            object_map, entry_point_name
        )

        return BOM(
            name,
            immutabledict(object_map),
            unresolved_sym_set,
            bss_size_required,
            entry_point_name,
            self._toolchain.segment_alignment,
        )

    def _create_object_file(
        self,
        file: str,
        header_dirs: List[str],
        out_dir: str,
        file_type: SourceFileType,
    ) -> Mapping[str, AssembledObject]:
        original_file = file
        if file.endswith(".S"):
            file = self._toolchain.preprocess(file, header_dirs, out_dir=out_dir)
        if file_type is SourceFileType.C:
            object_path = self._toolchain.compile(file, header_dirs, out_dir=out_dir)
        elif file_type is SourceFileType.ASM:
            object_path = self._toolchain.assemble(file, header_dirs, out_dir=out_dir)
        else:
            self.logger.error(f"Source file type '{file_type}' invalid, unable to prepare object.")
        obj = self.prepare_object(object_path)
        return {original_file: obj}

    def _resolve_symbols_within_BOM(
        self, object_map: Dict[str, AssembledObject], entry_point_name: Optional[str] = None
    ) -> Tuple[int, Set[str]]:
        bss_size_required = 0
        symbols: Dict[str, Tuple[int, LinkableSymbolType]] = {}
        unresolved_symbols: Dict[str, Tuple[int, LinkableSymbolType]] = {}
        for o in object_map.values():
            bss_size_required += o.bss_size_required
            symbols.update(o.strong_symbols)
            # Resolve symbols defined within different patch files within the same patch BOM
            for sym, values in o.unresolved_symbols.items():
                # Have not already seen this symbol in a previous patch object
                if sym not in symbols.keys():
                    unresolved_symbols.update({sym: values})

        unresolved_sym_set: Set[str]
        unresolved_sym_set = set(unresolved_symbols.keys()) - set(symbols.keys())

        if entry_point_name and entry_point_name not in symbols:
            raise PatchMakerException(f"Entry point {entry_point_name} not found in object files")

        return bss_size_required, unresolved_sym_set

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
        align = self._toolchain.segment_alignment
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

    # This deprecated method is no longer part of PatchMaker public API.
    async def allocate_bom(  # pragma: no cover
        self,
        allocatable,
        bom: BOM,
    ) -> PatchRegionConfig:
        warn(
            "PatchMaker.allocate_bom(allocatable, bom) is deprecated! Use "
            "allocatable.allocate_bom(bom) instead.",
            category=DeprecationWarning,
        )
        return await allocatable.allocate_bom(bom)
