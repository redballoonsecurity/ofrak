from ofrak_type.endianness import Endianness
from ofrak_type.bit_width import BitWidth
from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    ProcessorType,
)
from ofrak.core.architecture import ProgramAttributes
from ofrak_patch_maker.toolchain.version import ToolchainVersion

# These extensions are unused and ignored in the C tests

ARM_EXTENSION = ".arm"
AARCH64_EXTENSION = ".aarch64"
X86_EXTENSION = ".x86"
M68K_EXTENSION = ".m68k"

ARM_TOOLCHAINS_UNDER_TEST = [
    (
        ToolchainVersion.GNU_ARM_NONE_EABI_10_2_1,
        ProgramAttributes(
            InstructionSet.ARM,
            SubInstructionSet.ARMv8A,
            BitWidth.BIT_32,
            Endianness.LITTLE_ENDIAN,
            ProcessorType.GENERIC_A9_V7_THUMB,
        ),
        ARM_EXTENSION,
    ),
    (
        ToolchainVersion.LLVM_12_0_1,
        ProgramAttributes(
            InstructionSet.ARM,
            SubInstructionSet.ARMv8A,
            BitWidth.BIT_32,
            Endianness.LITTLE_ENDIAN,
            ProcessorType.GENERIC_A9_V7_THUMB,
        ),
        ARM_EXTENSION,
    ),
]

AARCH64_TOOLCHAINS_UNDER_TEST = [
    (
        ToolchainVersion.GNU_AARCH64_LINUX_10,
        ProgramAttributes(
            InstructionSet.AARCH64,
            None,
            BitWidth.BIT_32,
            Endianness.BIG_ENDIAN,
            ProcessorType.CORTEX_A53,
        ),
        AARCH64_EXTENSION,
    )
]

X86_TOOLCHAINS_UNDER_TEST = [
    (
        ToolchainVersion.GNU_X86_64_LINUX_EABI_10_3_0,
        ProgramAttributes(
            InstructionSet.X86,
            None,
            BitWidth.BIT_32,
            Endianness.LITTLE_ENDIAN,
            ProcessorType.X64,
        ),
        X86_EXTENSION,
    )
]

M68K_TOOLCHAINS_UNDER_TEST = [
    (
        ToolchainVersion.GNU_M68K_LINUX_10,
        ProgramAttributes(
            InstructionSet.M68K,
            None,
            BitWidth.BIT_32,
            Endianness.BIG_ENDIAN,
            ProcessorType.COLDFIRE4E,
        ),
        M68K_EXTENSION,
    ),
    (
        ToolchainVersion.VBCC_M68K_0_9,
        ProgramAttributes(
            InstructionSet.M68K,
            None,
            BitWidth.BIT_32,
            Endianness.BIG_ENDIAN,
            ProcessorType.COLDFIRE4E,
        ),
        M68K_EXTENSION,
    ),
]
