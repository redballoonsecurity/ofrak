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
