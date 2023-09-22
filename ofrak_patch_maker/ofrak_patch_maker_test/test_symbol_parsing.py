import logging
import os
from typing import Type, Tuple

import pytest

from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.gnu_aarch64 import GNU_AARCH64_LINUX_10_Toolchain
from ofrak_patch_maker.toolchain.gnu_arm import GNU_ARM_NONE_EABI_10_2_1_Toolchain
from ofrak_patch_maker.toolchain.gnu_avr import GNU_AVR_5_Toolchain
from ofrak_patch_maker.toolchain.gnu_ppc import GNU_PPC_LINUX_10_Toolchain, GNU_PPCVLE_4_Toolchain
from ofrak_patch_maker.toolchain.gnu_x64 import GNU_X86_64_LINUX_EABI_10_3_0_Toolchain
from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    CompilerOptimizationLevel,
)
from ofrak_type import *
from dataclasses import dataclass


@dataclass
class TestCase:
    base_label: str
    symbol_source_code: str
    expected_to_be_resolved: bool
    toolchain: Type[Toolchain]
    arch_info: ArchInfo

    @property
    def full_label(self) -> str:
        return f"{self.base_label}({self.toolchain.__name__}, {self.arch_info.isa.name})"


UNRESOLVED = False
RESOLVED = True
SYMBOL_NAME = "foo"


SYMBOL_SOURCES: List[Tuple[str, str, bool]] = [
    (
        "weak symbol",
        """
        __attribute__((weak)) int foo(){return 1;}
        """,
        UNRESOLVED,
    ),
    (
        "strong symbol",
        """
        int foo();
        int foo(){return 1;}
        """,
        RESOLVED,
    ),
    (
        "extern symbol",
        """
        extern int foo();

        int foo_caller() {return foo();}
        """,
        UNRESOLVED,
    ),
]


TOOLCHAINS_AND_TARGETS = [
    (
        LLVM_12_0_1_Toolchain,
        ArchInfo(InstructionSet.ARM, None, BitWidth.BIT_32, Endianness.LITTLE_ENDIAN, None),
    ),
    (
        GNU_ARM_NONE_EABI_10_2_1_Toolchain,
        ArchInfo(InstructionSet.ARM, None, BitWidth.BIT_32, Endianness.LITTLE_ENDIAN, None),
    ),
    # TODO: Error when running vbcc thru python/pytest; same command works on command line
    # (
    #     VBCC_0_9_GNU_Hybrid_Toolchain,
    #     ArchInfo(InstructionSet.M68K, None, BitWidth.BIT_32, Endianness.LITTLE_ENDIAN, None)
    # ),
    (
        GNU_X86_64_LINUX_EABI_10_3_0_Toolchain,
        ArchInfo(InstructionSet.X86, None, BitWidth.BIT_64, Endianness.LITTLE_ENDIAN, None),
    ),
    (
        GNU_PPC_LINUX_10_Toolchain,
        ArchInfo(InstructionSet.PPC, None, BitWidth.BIT_32, Endianness.BIG_ENDIAN, None),
    ),
    (
        GNU_PPCVLE_4_Toolchain,
        ArchInfo(
            InstructionSet.PPC,
            SubInstructionSet.PPCVLE,
            BitWidth.BIT_32,
            Endianness.BIG_ENDIAN,
            None,
        ),
    ),
    (
        GNU_AVR_5_Toolchain,
        ArchInfo(
            InstructionSet.AVR,
            SubInstructionSet.AVR2,
            BitWidth.BIT_32,
            Endianness.LITTLE_ENDIAN,
            None,
        ),
    ),
    (
        GNU_AARCH64_LINUX_10_Toolchain,
        ArchInfo(InstructionSet.AARCH64, None, BitWidth.BIT_64, Endianness.LITTLE_ENDIAN, None),
    ),
]


FULL_TEST_CASES = [
    TestCase(case_name, symbol_source, expected_resolved, toolchain, arch)
    for (case_name, symbol_source, expected_resolved) in SYMBOL_SOURCES
    for (toolchain, arch) in TOOLCHAINS_AND_TARGETS
]


@pytest.mark.parametrize("tc", FULL_TEST_CASES, ids=lambda case: case.full_label)
async def test_symbol_parsing(tc: TestCase, tmpdir):
    logging.getLogger().addHandler(logging.FileHandler("/tmp/ofrak.log"))
    logging.getLogger().setLevel(logging.INFO)

    toolchain = tc.toolchain(
        tc.arch_info,
        ToolchainConfig(
            file_format=BinFileType.ELF,
            force_inlines=False,
            relocatable=False,
            no_std_lib=True,
            no_jump_tables=True,
            no_bss_section=True,
            compiler_optimization_level=CompilerOptimizationLevel.NONE,
        ),
    )
    patch_maker = PatchMaker(toolchain, build_dir=tmpdir)

    source_path = os.path.join(tmpdir, f"src.c")
    with open(source_path, "w") as f:
        f.write(tc.symbol_source_code)

    bom = patch_maker.make_bom(
        "test_symbol_parsing",
        [source_path],
        [],
        [],
    )

    for obj in bom.object_map.values():
        if SYMBOL_NAME not in obj.strong_symbols and SYMBOL_NAME not in obj.unresolved_symbols:
            continue

        if tc.expected_to_be_resolved:
            assert SYMBOL_NAME in obj.strong_symbols, "symbol erroneously un-resolved!"
            return

        else:
            assert SYMBOL_NAME in obj.unresolved_symbols, "symbol erroneously resolved!"
            return

    pytest.fail(f"Expected symbol {SYMBOL_NAME} was not found in object file!")
