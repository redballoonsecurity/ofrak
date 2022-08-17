import logging
import os
import tempfile
from abc import ABC
from typing import Iterable, List, Mapping, Optional, Tuple, Dict
from warnings import warn

from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import InstructionSet, SubInstructionSet
from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser, GNU_V10_ELF_Parser
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


class Abstract_GNU_Toolchain(Toolchain, ABC):
    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)

        assert self.file_format == BinFileType.ELF

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
                #      get_required_alignment() doesn't quite make up for it
                #      if sections contain more than one function =/
                "-fno-merge-constants",  # avoids sections like .rodata.cst16, .rodata.str1.1 etc
                "-fno-reorder-functions",
                "-Wall",
            ]
        )
        if self._config.separate_data_sections:
            self._compiler_flags.append("-fdata-sections")

        if not self._config.userspace_dynamic_linker:
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

    @property
    def name(self) -> str:
        raise NotImplementedError()

    def _get_compiler_target(self, processor: ProgramAttributes) -> Optional[str]:
        return self._config.compiler_target

    @property
    def _linker_script_flag(self) -> str:
        return "-T"

    @staticmethod
    def _get_linker_map_flag(exec_path: str) -> Iterable[str]:
        return "-Map", f"{exec_path}.map"

    def keep_section(self, section_name: str):
        if section_name in self._linker_keep_list:
            return True
        if self._config.separate_data_sections:
            for keep_section in self._linker_keep_list:
                if section_name.startswith(keep_section):
                    return True
            return False
        else:
            return False

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
            f"    {bss_section_name} : {{\n"
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

    def get_required_alignment(self, segment: Segment) -> int:
        if self._processor.isa == InstructionSet.X86:
            return 16
        return 1

    def get_bin_file_symbols(self, executable_path: str) -> Dict[str, int]:
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


class GNU_10_Toolchain(Abstract_GNU_Toolchain):
    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)

        if self._compiler_target is not None:
            self._compiler_flags.append(f"-march={self._compiler_target}")
        if self._config.compiler_cpu:
            self._compiler_flags.append(f"-mcpu={self._config.compiler_cpu}")

        self._assembler_flags.append(f"-march={self._get_assembler_target(processor)}")
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


class GNU_ARM_NONE_EABI_10_2_1_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        if self._config.hard_float:
            self._compiler_flags.append("-mfloat-abi=hard")
        else:
            self._compiler_flags.append("-msoft-float")

    @property
    def name(self):
        return "GNU_ARM_NONE"

    def _get_assembler_target(self, processor: ProgramAttributes):
        """
        Thumb mode should be defined in the assembler source at the top, using:

            .syntax unified
            .thumb           ; or .code 16
        """
        if processor.isa is not InstructionSet.ARM:
            raise ValueError(
                f"The GNU ARM toolchain does not support ISAs which are not ARM; "
                f"given ISA {processor.isa.name}"
            )
        if self._config.assembler_target:
            return self._config.assembler_target

        if processor.sub_isa:
            return processor.sub_isa.value.lower()
        elif processor.isa == InstructionSet.ARM:
            return SubInstructionSet.ARMv7A.value.lower()
        else:
            raise ToolchainException("Assembler Target not provided and no valid default found!")


class GNU_X86_64_LINUX_EABI_10_3_0_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_V10_ELF_Parser()]

    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)

        self._compiler_flags.extend(
            [
                "-malign-data=abi",  # further relaxes compiler data alignment policy
                "-mno-sse2",  # restricts usage of xmm register / avx instruction usage.
            ]
        )

        if not self._config.hard_float:
            self._compiler_flags.append("-msoft-float")

    @property
    def name(self) -> str:
        return "GNU_X86_64_LINUX"

    def _get_assembler_target(self, processor: ProgramAttributes):
        if self._config.assembler_target:
            return self._config.assembler_target
        return "generic64"

    @staticmethod
    def ld_generate_bss_section(
        memory_region_name: str,
    ) -> str:
        """
        We override this for x64 so we can provide SUBALIGN(1)
        This is required to correctly estimate how much size we need for bss
        when splitting up data structures into their own individual bss sections.
        If we were to let the linker align every structure's section to 8 or 16, it would
        insert empty space that we had not allocated for the bss memory region.
        gcc/ld do prefer 8 alignment for data if you don't force this, but it is not likely to be
        hugely faster on recent hardware for most situations (ie not locked instructions
        across a cache line):
        https://lemire.me/blog/2012/05/31/data-alignment-for-speed-myth-or-reality/
        Pre-2011 x64 chips might be slower with these kinds of accesses, but:
           - We should not bend over backwards for processors we've not evaluated yet.
           - .bss handling is already difficult enough as is.
           - The flexibility granted by this feature likely justifies a relatively small performance impact.
        We should address this as a problem if future users find that performance is noticeably/severely impacted.
        """
        bss_section_name = ".bss"
        return (
            f"    {bss_section_name} : SUBALIGN(1) {{\n"
            f"        *.o({bss_section_name}, {bss_section_name}.*)\n"
            f"    }} > {memory_region_name}"
        )


class GNU_M68K_LINUX_10_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        if self._config.hard_float:
            self._compiler_flags.append("-mfloat-abi=hard")
        else:
            self._compiler_flags.append("-msoft-float")

    @property
    def name(self):
        return "GNU_M68K_LINUX_10"

    def get_required_alignment(self, segment: Segment) -> int:
        return 4

    def _get_assembler_target(self, processor: ProgramAttributes):
        if processor.isa is not InstructionSet.M68K:
            raise ValueError(
                f"The GNU M68K toolchain does not support ISAs which are not M68K; "
                f"given ISA {processor.isa.name}"
            )
        if self._config.assembler_target:
            return self._config.assembler_target
        arch = processor.isa.value
        if processor.sub_isa is not None:
            arch = processor.sub_isa.value
        return arch

    def _ld_generate_rel_dyn_region(
        self,
        vm_address: int,
        length: int,
    ) -> Tuple[str, str]:
        region_name = '".rela.dyn_mem"'
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
        rel_dyn_section_name = ".rela.dyn"
        return (
            f"    {rel_dyn_section_name} : {{\n"
            f"        *.o({rel_dyn_section_name})\n"
            f"    }} > {memory_region_name}"
        )


class GNU_AARCH64_LINUX_10_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_V10_ELF_Parser()]

    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        # Enable compilation of the GNU atomics intrinsics.
        self._compiler_flags.append("-mno-outline-atomics")

    @property
    def name(self):
        return "GNU_AARCH64_LINUX_10"

    def get_required_alignment(self, segment: Segment) -> int:
        return 4

    def _ld_generate_got_region(self, vm_address, length):
        region_name = '".got_mem"'
        perms_string = self._ld_perm2str(MemoryPermissions.R)
        return (
            f"    {region_name} ({perms_string}) : ORIGIN = {hex(vm_address)}, "
            f"LENGTH = {hex(length)}",
            region_name,
        )

    def ld_generate_placeholder_reloc_sections(self):
        regions, sections = super().ld_generate_placeholder_reloc_sections()
        (
            got_region,
            got_name,
        ) = self._ld_generate_got_region(0xDEADBEEF + 0x30000, 0x1000)
        regions.append(got_region)
        sections.append(self._ld_generate_got_section(got_name))
        return regions, sections

    def _ld_generate_rel_dyn_region(
        self,
        vm_address: int,
        length: int,
    ) -> Tuple[str, str]:
        region_name = '".rela.dyn_mem"'
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
        rel_dyn_section_name = ".rela.dyn"
        return (
            f"    {rel_dyn_section_name} : {{\n"
            f"        *.o({rel_dyn_section_name})\n"
            f"    }} > {memory_region_name}"
        )

    def _get_assembler_target(self, processor: ProgramAttributes):
        if processor.isa is not InstructionSet.AARCH64:
            raise ValueError(
                f"The GNU AARCH64 toolchain does not support ISAs which are not AARCH64; "
                f"given ISA {processor.isa.name}"
            )
        if processor.sub_isa is not None:
            return processor.sub_isa.value.lower()
        return SubInstructionSet.ARMv8A.value.lower()


class GNU_AVR_5_Toolchain(Abstract_GNU_Toolchain):
    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)

        if self._config.relocatable:
            raise ValueError("-pie not supported for AVR")

        if toolchain_config.hard_float:
            raise ValueError("hard float not supported for AVR")

        # avr-gcc's -mmcu flag allows you to specify either the exact target chip, or a chip
        #      architecture. Specifying an exact chip will choose the correct avr/io.h and startup
        #      code for the chip. Here, we will first look for an exact chip supplied in the
        #      ToolchainConfig, and fall back on sub-ISA.
        #      See https://gcc.gnu.org/wiki/avr-gcc#Supporting_.22unsupported.22_Devices
        if processor.sub_isa is not None:
            self._linker_flags.append(f"-m{processor.sub_isa.value}")
            self._compiler_flags.append(
                f"-mmcu={self._config.compiler_cpu or processor.sub_isa.value}"
            )
            self._assembler_flags.append(
                f"-mmcu={self._config.assembler_cpu or processor.sub_isa.value}"
            )
        else:
            raise ValueError("sub_isa is required for AVR linking")

    @property
    def name(self) -> str:
        return "GNU_AVR_5"

    def _get_assembler_target(self, processor: ProgramAttributes) -> str:
        if processor.isa is not InstructionSet.AVR:
            raise ValueError(
                f"The GNU AVR toolchain does not support ISAs which are not AVR; "
                f"given ISA {processor.isa.name}"
            )
        if self._config.assembler_target:
            return self._config.assembler_target
        return InstructionSet.AVR.value.lower()

    def get_required_alignment(self, segment: Segment) -> int:
        return 2
