import logging
from os.path import join, split
from abc import ABC
from typing import List
from warnings import warn
import itertools
import re

from ofrak_patch_maker.toolchain.gnu import Abstract_GNU_Toolchain

from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import InstructionSet
from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser
from ofrak_patch_maker.toolchain.model import (
    BinFileType,
    ToolchainConfig,
    CompilerOptimizationLevel,
)


class VBCC_0_9_GNU_Hybrid_Toolchain(Abstract_GNU_Toolchain, ABC):
    """
    A hybrid toolchain using the VBCC compiler + GNU assembler and linker.
    """

    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(
        self,
        processor: ProgramAttributes,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        # Skip the GNU __init__ routine, but keep the Toolchain __init__.
        super(Abstract_GNU_Toolchain, self).__init__(processor, toolchain_config, logger=logger)

        assert self.file_format == BinFileType.ELF

        self._preprocessor_flags.append("-E")

        self._compiler_flags.extend(
            [
                "-gas",
                "-cpp-comments",
                "-warn=-1",
                # "-stack-check",  # TODO: Look into this...
            ]
        )
        if self._config.separate_data_sections:
            self._compiler_flags.append("-sec-per-obj")

        if self._compiler_target is not None:
            pass

        if self._config.compiler_cpu:
            # Defaults to 68000
            self._compiler_flags.append(f"-cpu={self._config.compiler_cpu}")

        if not self._config.userspace_dynamic_linker:
            self._linker_flags.append(
                "--no-dynamic-linker",
            )

        vbcc_compiler_optimization_map = {
            CompilerOptimizationLevel.NONE: "",
            CompilerOptimizationLevel.SOME: "",
            CompilerOptimizationLevel.SPACE: "-size",
            # TODO: Look into O=16384 for full cross-module optimizations. Bit encoded.
            CompilerOptimizationLevel.FULL: "-speed",
        }
        self._compiler_flags.append(
            vbcc_compiler_optimization_map[self._config.compiler_optimization_level]
        )

        if not self._config.hard_float:
            self._compiler_flags.append("-soft-float")

        if self._config.force_inlines:
            warn("Warning: force_inlines not supported for this toolchain!")

        if self._config.relocatable:
            warn("Warning: relocatable not supported for this toolchain!")

        if self._config.no_std_lib:
            warn("Warning: -nostdlib already implied for this compiler backend!")

        if self._config.no_bss_section:
            # -use-commons?
            warn("Warning: relocatable not supported for this toolchain!")

        # Same as LLVM
        if self._config.no_jump_tables:
            warn("Warning: no_jump_tables not supported for this toolchain!")

        if self._config.debug_info:
            self._compiler_flags.append("-g")

        self._linker_flags.extend(
            [
                "--error-unresolved-symbols",
                "--warn-section-align",
                "--nmagic",  # Do not page align data
                "--no-eh-frame-hdr",
            ]
        )

        # Same as LLVM
        if not self._config.check_overlap:
            self._linker_flags.append("--no-check-sections")

        self._assembler_flags.append(f"-march={self._get_assembler_target(processor)}")
        if self._config.assembler_cpu:
            self._assembler_flags.append(f"-mcpu={self._config.assembler_cpu}")

        if toolchain_config.isysroot is not None:
            pass

    @property
    def name(self):
        return "VBCC_M68K_0_9"

    @staticmethod
    def _make_gas_compatible(in_file: str) -> str:
        def add_percent(lines: List[str]) -> List[str]:
            new_lines = list()
            pattern = re.compile(r"[,(\s][ad]\d{1,2}")
            for line in lines:
                line = line.replace("@", "")
                splits = pattern.split(line)
                matches = pattern.findall(line)
                new_line = list()
                for i, j in itertools.zip_longest(splits, matches):
                    if i is not None:
                        new_line.append(i)
                    if j is not None:
                        new_j = j[0] + "%" + j[1:]
                        new_line.append(new_j)
                new_lines.append("".join(new_line))
            return new_lines

        with open(in_file) as f:
            lines = f.readlines()

        new_lines = add_percent(lines)

        with open(in_file, "w") as f:
            f.write("".join(new_lines))

        return in_file

    def compile(self, c_file: str, header_dirs: List[str], out_dir: str = ".") -> str:
        """
        Modified version for vbcc hybrid functionality.
        """

        out_file = join(out_dir, split(c_file)[-1] + ".asm")
        self._execute_tool(
            self._compiler_path,
            self._compiler_flags,
            [c_file] + ["-I" + x for x in header_dirs],
            # vbcc expects an equality statement for this flag...
            out_file="=" + out_file,
        )
        self._make_gas_compatible(out_file)
        return self.assemble(out_file, header_dirs, out_dir)

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
