import logging
import os
import tempfile
from typing import List, Mapping, Optional, Tuple, Dict

from ofrak.core.architecture import ProgramAttributes
from ofrak_patch_maker.binary_parser.llvm import LLVM_ELF_Parser, LLVM_MACH_O_Parser
from ofrak_patch_maker.toolchain.abstract import Toolchain, RBS_AUTOGEN_WARNING
from ofrak_patch_maker.toolchain.model import (
    Segment,
    BinFileType,
    ToolchainConfig,
    CompilerOptimizationLevel,
    ToolchainException,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_type.architecture import InstructionSet
from ofrak_type.memory_permissions import MemoryPermissions


class LLVM_12_0_1_Toolchain(Toolchain):
    binary_file_parsers = [LLVM_ELF_Parser(), LLVM_MACH_O_Parser()]

    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        assert self.file_format in [
            BinFileType.ELF,
            BinFileType.COFF,
            BinFileType.MACH_O,
        ], f"Unsupported file type for {__name__}"

        self._preprocessor_flags.append("-E")

        self._assembler_flags.append(f"-march={self._assembler_target}")
        if self._config.assembler_cpu:
            self._assembler_flags.append(f"-mcpu={self._config.assembler_cpu}")
        self._compiler_flags.extend(
            [
                "-cc1",
                "-triple",
                self._compiler_target,  # type: ignore
                "-emit-obj",
                "-msoft-float",
                "-mfloat-abi",
                "soft",
                "-Wall",
            ]
        )

        if self._config.separate_data_sections:
            raise NotImplementedError("separate sections not supported by LLVM Toolchain yet")
        if self._config.compiler_cpu:
            self._compiler_flags.append(f"-mcpu={self._config.compiler_cpu}")

        llvm12_compiler_optimization_map = {
            CompilerOptimizationLevel.NONE: "-O0",
            CompilerOptimizationLevel.SOME: "-O1",
            CompilerOptimizationLevel.SPACE: "-Oz",
            CompilerOptimizationLevel.FULL: "-O3",
        }
        self._compiler_flags.append(
            llvm12_compiler_optimization_map[self._config.compiler_optimization_level]
        )

        if not self._config.userspace_dynamic_linker:
            self._compiler_flags.append("-ffreestanding")

        if self._config.force_inlines:
            self._compiler_flags.append("-finline-hint-functions")

        if self._config.relocatable:
            self._compiler_flags.extend(["-fno-direct-access-external-data", "-pic-is-pie"])
            self._linker_flags.append("--pie")
        else:
            self._linker_flags.append("--no-pie")

        if self._config.no_bss_section:
            self._compiler_flags.append("-fno-zero-initialized-in-bss")

        if self._config.no_jump_tables:
            self._compiler_flags.append("-fno-jump-tables")

        if self._config.debug_info:
            self._compiler_flags.extend(
                [
                    "-fno-split-dwarf-inlining",
                    "-debug-info-kind=limited",
                    "-dwarf-version=4",
                    "-debugger-tuning=gdb",
                ]
            )

        self._linker_flags.extend(
            [
                "--error-unresolved-symbols",
                "--warn-symbol-ordering",
                "-mllvm",
                # Since we are doing some non-standard linking with the way we allocate locations,
                # we require that the user of the Toolchain handle alignment themselves so they
                # can be sure where everything ends up. The linker should not make any assumptions
                # about where it's OK to put things; it should put stuff exactly where we say.
                "--align-all-functions=1",
            ]
        )
        if not self._config.check_overlap:
            self._linker_flags.append("--no-check-sections")

    @property
    def name(self) -> str:
        return "LLVM_12_0_1"

    def _get_assembler_target(self, processor: ProgramAttributes) -> str:
        arch = processor.isa.value
        if self._config.assembler_target:
            return self._config.assembler_target
        elif arch == InstructionSet.ARM.value:
            return "armv7-a"
        elif arch == InstructionSet.X86.value:
            return "generic64"
        else:
            raise ToolchainException("Assembler Target not provided and no valid default found!")

    def _get_compiler_target(self, processor: ProgramAttributes) -> Optional[str]:
        arch = processor.isa.value
        if self._config.compiler_target:
            return self._config.compiler_target
        if arch == InstructionSet.ARM.value:
            return "armv7---elf"
        elif arch == InstructionSet.X86.value:
            return "amd64---elf"
        else:
            raise ToolchainException("Compiler Target not provided and no valid default found!")

    @property
    def _linker_script_flag(self) -> str:
        return "-T"

    def compile(self, c_file: str, header_dirs: List[str], out_dir: str = ".") -> str:
        if self._config.userspace_dynamic_linker:
            out_file = os.path.join(out_dir, os.path.split(c_file)[-1] + ".o")
            # For now a complete override of the flags; we sidestep the clang front-end
            # in favor of a more userspace-friendly GNU configuration.
            self._execute_tool(
                self._compiler_path,
                ["-O3", "-Wall", "-g", "-fPIE", "-c"],
                [c_file] + ["-I" + x for x in header_dirs],
                out_file=out_file,
            )
            return os.path.abspath(out_file)
        else:
            return super().compile(c_file, header_dirs, out_dir=out_dir)

    def link(self, o_files: List[str], exec_path: str, script=None):
        if self._config.userspace_dynamic_linker:
            # We will ignore the script and any lld flags in this case
            flags = [
                f"--dynamic-linker={self._config.userspace_dynamic_linker}",
                f"-L{self._lib_path}",
            ]
            return self._execute_tool(self._linker_path, flags, o_files, out_file=exec_path)
        else:
            return super().link(o_files, exec_path, script=script)

    @staticmethod
    def _get_linker_map_flag(exec_path: str):
        return (f"--Map={exec_path}.map",)

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

    @staticmethod
    def ld_generate_bss_region(
        vm_address: int,
        length: int,
    ) -> Tuple[str, str]:
        region_name = ".bss_mem"
        perms_string = LLVM_12_0_1_Toolchain._ld_perm2str(MemoryPermissions.RW)
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
            f"    .rbs_{stripped_obj_name}_{stripped_seg_name} : {{\n"
            f"        {abs_path}({segment_name})\n"
            f"    }} > {memory_region_name}"
        )

    @staticmethod
    def ld_generate_bss_section(
        memory_region_name: str,
    ) -> str:
        bss_section_name = ".bss"
        return (
            f"    {bss_section_name} : {{\n"
            f"        *.o({bss_section_name})\n"
            f"    }} > {memory_region_name}"
        )

    def ld_script_create(
        self,
        name: str,
        memory_regions: List[str],
        sections: List[str],
        build_dir: str,
        symbol_files: List[str],
    ) -> str:
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

    def get_required_alignment(self, segment: Segment) -> int:
        # The linker will align function starts to 16-byte boundaries
        # https://patchwork.kernel.org/project/kernel-hardening/patch/20200205223950.1212394-7-kristen@linux.intel.com/
        # Plus, some other memory will also be aligned to 16
        # https://stackoverflow.com/a/49397524/2753454
        # Let's just do it for every section; we already allocated 16 extra earlier
        if self._processor.isa == InstructionSet.X86:
            return 16
        return 1

    def get_bin_file_symbols(self, executable_path: str) -> Dict[str, int]:
        readobj_output = self._execute_tool(
            self._readobj_path, ["--symbols"], [executable_path], out_file=None
        )

        return self._parser.parse_symbols(readobj_output)

    def get_bin_file_segments(self, path: str) -> Tuple[Segment, ...]:
        """
        :return: list of segments
        """
        if get_file_format(path) != self.file_format:
            raise ToolchainException(
                "Extracted file format does not match this toolchain instance!"
            )

        readobj_output = self._execute_tool(
            self._readobj_path, ["--section-details"], [path], out_file=None
        )

        return self._parser.parse_sections(readobj_output)
