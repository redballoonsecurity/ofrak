import logging
import os
import tempfile
from abc import ABC, abstractmethod
from typing import Iterable, List, Mapping, Optional, Tuple, Dict
from warnings import warn

from ofrak_type import ArchInfo
from ofrak_patch_maker.toolchain.abstract import Toolchain, RBS_AUTOGEN_WARNING
from ofrak_patch_maker.toolchain.model import (
    Segment,
    BinFileType,
    ToolchainConfig,
    CompilerOptimizationLevel,
    ToolchainException,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.symbol_type import LinkableSymbolType


class Abstract_GNU_Toolchain(Toolchain, ABC):
    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)

        if self.file_format != BinFileType.ELF:
            raise ToolchainException("No supported binary file formats other than ELF for now.")

        self._preprocessor_flags.append("-E")

        self._compiler_flags.extend(
            [
                "-ffreestanding",
                "-Wall",
                "-c",
                "-fno-align-functions",  # This is to make sure code sections get put exactly
                #      where we allocated them... e.g. hooks.
                # The downside is that it applies to all functions in a
                #      section, so our manual alignment of sections with
                #      segment_alignment doesn't quite make up for it
                #      if sections contain more than one function =/
                "-fno-merge-constants",  # avoids sections like .rodata.cst16, .rodata.str1.1 etc
                "-fno-reorder-functions",
                "-Wall",
            ]
        )
        if self._config.separate_data_sections:
            self._compiler_flags.append("-fdata-sections")

        if not self.is_userspace():
            self._linker_flags.append(
                "--no-dynamic-linker",
            )

        gnu10_compiler_optimization_map = {
            CompilerOptimizationLevel.NONE: "-O0",
            CompilerOptimizationLevel.SOME: "-O1",
            CompilerOptimizationLevel.SPACE: "-Os",
            CompilerOptimizationLevel.FULL: "-O3",
        }
        self._compiler_flags.append(
            gnu10_compiler_optimization_map[self._config.compiler_optimization_level]
        )

        if self._config.force_inlines:
            # Does not actually force functions with "inline" keyword to be inlined
            warn("Inlining is enabled, but use __attribute__((always_inline)) to be sure.")
            self._compiler_flags.append("-finline-functions")

        # TODO: If we start using this we will need an RBS-provided "--sysroot" somewhere in here
        #  with our own implemented (not copied) versions of stdint.h, stddef.h, and so on...
        if self._config.no_std_lib:
            self._compiler_flags.append("-nostdlib")

        if self._config.no_bss_section:
            self._compiler_flags.append("-fno-zero-initialized-in-bss")

        # Same as LLVM
        if self._config.no_jump_tables:
            self._compiler_flags.append("-fno-jump-tables")

        if self._config.debug_info:
            self._compiler_flags.append("-g")

        self._linker_flags.extend(
            [
                "--error-unresolved-symbols",
                "--warn-section-align",
                "--nmagic",  # Do not page align data
            ]
        )

        # Same as LLVM
        if not self._config.check_overlap:
            self._linker_flags.append("--no-check-sections")

        if toolchain_config.isysroot is not None:
            self._compiler_flags.append(f"-isysroot {toolchain_config.isysroot}")

    def _get_compiler_target(self, processor: ArchInfo) -> Optional[str]:
        return self._config.compiler_target

    @property
    def _linker_script_flag(self) -> str:
        return "-T"

    @staticmethod
    def _get_linker_map_flag(exec_path: str) -> Iterable[str]:
        return "-Map", f"{exec_path}.map"

    def add_linker_include_values(self, symbols: Mapping[str, int], path: str):
        with open(path, "a") as f:
            for name, addr in symbols.items():
                if self.linker_include_filter(name):
                    continue
                f.write(f"PROVIDE({name} = {hex(addr)});\n")

    def generate_linker_include_file(self, symbols: Mapping[str, int], out_path: str) -> str:
        with open(out_path, "w") as f:
            f.write(RBS_AUTOGEN_WARNING)

        self.add_linker_include_values(symbols, out_path)
        return out_path

    @staticmethod
    def _ld_perm2str(p: MemoryPermissions) -> Optional[str]:
        perm = p.as_str()
        if perm in ["r", "rw", "rx", "rwx", "w"]:
            return perm
        else:
            raise ToolchainException(f"Invalid access permissions: {p}")

    def ld_generate_region(
        self,
        object_path: str,
        segment_name: str,
        permissions: MemoryPermissions,
        vm_address: int,
        length: int,
    ) -> Tuple[str, str]:
        perms_string = self._ld_perm2str(permissions)
        stripped_seg_name = segment_name.strip(".")
        stripped_obj_name = os.path.basename(object_path).split(".")[0]
        region_name = f'".rbs_{stripped_obj_name}_{stripped_seg_name}_mem"'
        return (
            f"    {region_name} ({perms_string}) : ORIGIN = {hex(vm_address)}, LENGTH = {hex(length)}",
            region_name,
        )

    def ld_generate_bss_region(
        self,
        vm_address: int,
        length: int,
    ) -> Tuple[str, str]:
        region_name = '".bss_mem"'
        perms_string = self._ld_perm2str(MemoryPermissions.RW)
        return (
            f"    {region_name} ({perms_string}) : ORIGIN = {hex(vm_address)}, LENGTH = {hex(length)}",
            region_name,
        )

    @staticmethod
    def ld_generate_section(
        object_path: str,
        segment_name: str,
        memory_region_name: str,
    ) -> str:
        stripped_seg_name = segment_name.strip(".")
        stripped_obj_name = os.path.basename(object_path).split(".")[0]
        abs_path = os.path.abspath(object_path)
        return (
            f"    .rbs_{stripped_obj_name}_{stripped_seg_name} ORIGIN({memory_region_name}) : SUBALIGN(0) {{\n"
            f"        {abs_path}({segment_name})\n"
            f"    }} > {memory_region_name}"
        )

    @staticmethod
    def ld_generate_bss_section(
        memory_region_name: str,
    ) -> str:
        bss_section_name = ".bss"
        return (
            f"    {bss_section_name} : SUBALIGN(0) {{\n"
            f"        *.o({bss_section_name}, {bss_section_name}.*)\n"
            f"    }} > {memory_region_name}"
        )

    def _ld_generate_got_plt_region(
        self,
        vm_address: int,
        length: int,
    ) -> Tuple[str, str]:
        region_name = '".got.plt_mem"'
        perms_string = self._ld_perm2str(MemoryPermissions.R)
        return (
            f"    {region_name} ({perms_string}) : ORIGIN = {hex(vm_address)}, "
            f"LENGTH = {hex(length)}",
            region_name,
        )

    @staticmethod
    def _ld_generate_got_plt_section(
        memory_region_name: str,
    ) -> str:
        got_plt_section_name = ".got.plt"
        return (
            f"    {got_plt_section_name} : {{\n"
            f"        *.o({got_plt_section_name})\n"
            f"    }} > {memory_region_name}"
        )

    @staticmethod
    def _ld_generate_got_section(
        memory_region_name: str,
    ) -> str:
        got_plt_section_name = ".got"
        return (
            f"    {got_plt_section_name} : {{\n"
            f"        *.o({got_plt_section_name})\n"
            f"    }} > {memory_region_name}"
        )

    def _ld_generate_rel_dyn_region(
        self,
        vm_address: int,
        length: int,
    ) -> Tuple[str, str]:
        region_name = '".rel.dyn_mem"'
        perms_string = self._ld_perm2str(MemoryPermissions.RW)
        return (
            f"    {region_name} ({perms_string}) : ORIGIN = {hex(vm_address)}, "
            f"LENGTH = {hex(length)}",
            region_name,
        )

    @staticmethod
    def _ld_generate_rel_dyn_section(
        memory_region_name: str,
    ) -> str:
        rel_dyn_section_name = ".rel.dyn"
        return (
            f"    {rel_dyn_section_name} : {{\n"
            f"        *.o({rel_dyn_section_name})\n"
            f"    }} > {memory_region_name}"
        )

    def ld_generate_placeholder_reloc_sections(self) -> Tuple[List[str], List[str]]:
        """
        GCC generates these sections for relocatable binaries even if they are completely
        unnecessary.

        They don't seem to make it into the final executable, so there should be no risk
        of injecting them inadvertently.

        !!! todo

            No clear way to get size, so way overestimate.
        """
        (
            got_plt_region,
            got_plt_name,
        ) = self._ld_generate_got_plt_region(0xDEADBEEF, 0x1000)
        got_plt_section = self._ld_generate_got_plt_section(got_plt_name)
        (
            rel_dyn_region,
            rel_dyn_name,
        ) = self._ld_generate_rel_dyn_region(0xDEADBEEF + 0x20000, 0x1000)
        rel_dyn_section = self._ld_generate_rel_dyn_section(rel_dyn_name)
        return [got_plt_region, rel_dyn_region], [got_plt_section, rel_dyn_section]

    def ld_script_create(
        self,
        name: str,
        memory_regions: List[str],
        sections: List[str],
        build_dir: str,
        symbol_files: List[str],
    ) -> str:
        # I know that it's annoying we're duplicating all of this source
        # from the LLVM implementation, but ultimately each toolchain
        # is responsible for maintaining its own syntax.
        _, ld_script_path = tempfile.mkstemp(dir=build_dir, prefix=name + "_", suffix=".ld")
        with open(ld_script_path, "w") as f:
            f.write(RBS_AUTOGEN_WARNING)
            for file in symbol_files:
                f.write(f"INCLUDE {str(os.path.abspath(file))}\n")

            f.write("\n\n")

            f.write("MEMORY\n{\n")
            for r in memory_regions:
                f.write(r + "\n")
            f.write("}\n")

            f.write("\n")

            f.write("SECTIONS\n{\n")
            for s in sections:
                f.write(s + "\n")
            f.write("\n")

            f.write("    /DISCARD/ : {\n")
            for d in self._linker_discard_list:
                f.write(f"        *({d})\n")
            f.write("    }\n")

            f.write("}\n")

        return ld_script_path

    @property
    @abstractmethod
    def segment_alignment(self) -> int:
        raise NotImplementedError()

    def get_bin_file_symbols(
        self, executable_path: str
    ) -> Dict[str, Tuple[int, LinkableSymbolType]]:
        # This happens to be the same as LLVM but it really doesn't belong in Parent code.
        # Note: readobj for gcc is objdump
        readobj_output = self._execute_tool(self._readobj_path, ["--syms"], [executable_path])

        return self._parser.parse_symbols(readobj_output)

    def get_bin_file_segments(self, path: str) -> Tuple[Segment, ...]:
        if get_file_format(path) != self.file_format:
            raise ToolchainException(
                "Extracted file format does not match this toolchain instance!"
            )

        readobj_output = self._execute_tool(self._readobj_path, ["--section-headers"], [path])

        return self._parser.parse_sections(readobj_output)

    def get_bin_file_rel_symbols(
        self, executable_path: str
    ) -> Dict[str, Tuple[int, LinkableSymbolType]]:
        readobj_output = self._execute_tool(self._readobj_path, ["--syms"], [executable_path])

        return self._parser.parse_relocations(readobj_output)


class GNU_10_Toolchain(Abstract_GNU_Toolchain):
    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)

        if self._compiler_target is not None:
            self._compiler_flags.append(f"-march={self._compiler_target}")
        if self._config.compiler_cpu:
            self._compiler_flags.append(f"-mcpu={self._config.compiler_cpu}")

        if self._assembler_target is not None:
            self._assembler_flags.append(f"-march={self._assembler_target}")
        if self._config.assembler_cpu:
            self._assembler_flags.append(f"-mcpu={self._config.assembler_cpu}")

        self._linker_flags.append(
            "--no-eh-frame-hdr",
        )

        if self._config.relocatable:
            self._compiler_flags.append("-pie")
            self._linker_flags.append("--pic-executable")
        else:
            self._compiler_flags.append("-fno-plt")
            self._compiler_flags.append("-fno-pic")
