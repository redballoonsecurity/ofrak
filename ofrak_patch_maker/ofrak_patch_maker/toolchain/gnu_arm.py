from typing import Optional, cast

from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser
from ofrak_patch_maker.toolchain.gnu import GNU_10_Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig, ToolchainException
from ofrak_type.architecture import InstructionSet, SubInstructionSet, ArchInfo
import logging


class GNU_ARM_NONE_EABI_10_2_1_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_ELF_Parser()]
    DEFAULT_ARM_VERSION: SubInstructionSet = SubInstructionSet.ARMv7A

    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        if self._config.hard_float:
            self._compiler_flags.append("-mfloat-abi=hard")
        else:
            self._compiler_flags.append("-msoft-float")

        if self._config.relocatable:
            # Use "PIC" instead of "PIE" for ARM relocatable binaries
            # This is a result of subtle differences between "PIC" and "PIE" code and how GNU emits code for each
            # The potential error, when compiling with `-pie` is:
            # relocation R_ARM_MOVW_ABS_NC against `a local symbol' can not be used when making a shared object; recompile with -fPIC

            # This is possibly a bug: https://binutils.sourceware.narkive.com/iz2t6r3I/link-problems-with-section-anchors
            # Or, possibly, the bug is in the abstract GNU toolchain, as it uses the `-pie` compiler flag but a `--pic-executable` for the linker flag
            # The subtle differences between PIC and PIE are maybe what is causing this error
            # But, an error only arises for the ARM toolchain, and coercing all GNU toolchains to use `-fpic`breaks other toolchain tests
            self._compiler_flags.remove("-pie")
            self._compiler_flags.append("-fpic")

    @property
    def name(self) -> str:
        return "GNU_ARM_NONE_EABI_10_2_1"

    @property
    def segment_alignment(self) -> int:
        return 4

    def _get_assembler_target(self, processor: ArchInfo):
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
            return cast(str, self.DEFAULT_ARM_VERSION.value).lower()
        else:
            raise ToolchainException("Assembler Target not provided and no valid default found!")

    def _get_compiler_target(self, processor: ArchInfo) -> Optional[str]:
        if self._config.compiler_target is None:
            return cast(str, self.DEFAULT_ARM_VERSION.value).lower()
        else:
            return self._config.compiler_target
