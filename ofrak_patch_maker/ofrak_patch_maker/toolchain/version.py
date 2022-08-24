from enum import Enum

from ofrak_patch_maker.toolchain.gnu import (
    GNU_ARM_NONE_EABI_10_2_1_Toolchain,
    GNU_X86_64_LINUX_EABI_10_3_0_Toolchain,
    GNU_M68K_LINUX_10_Toolchain,
    GNU_AARCH64_LINUX_10_Toolchain,
    GNU_AVR_5_Toolchain,
)
from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain
from ofrak_patch_maker.toolchain.vbcc_gnu_hybrid import VBCC_0_9_GNU_Hybrid_Toolchain


class ToolchainVersion(Enum):
    LLVM_12_0_1 = LLVM_12_0_1_Toolchain
    GNU_ARM_NONE_EABI_10_2_1 = GNU_ARM_NONE_EABI_10_2_1_Toolchain
    GNU_X86_64_LINUX_EABI_10_3_0 = GNU_X86_64_LINUX_EABI_10_3_0_Toolchain
    GNU_M68K_LINUX_10 = GNU_M68K_LINUX_10_Toolchain
    VBCC_M68K_0_9 = VBCC_0_9_GNU_Hybrid_Toolchain
    GNU_AARCH64_LINUX_10 = GNU_AARCH64_LINUX_10_Toolchain
    GNU_AVR_5 = GNU_AVR_5_Toolchain
