from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser
from ofrak_patch_maker.toolchain.gnu import Abstract_GNU_Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig
from ofrak_type.architecture import InstructionSet, ArchInfo
import logging


class GNU_AVR_5_Toolchain(Abstract_GNU_Toolchain):
    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(
        self,
        processor: ArchInfo,
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
            self._preprocessor_flags.append(
                f"-mmcu={self._config.compiler_cpu or processor.sub_isa.value}"
            )
        else:
            raise ValueError("sub_isa is required for AVR linking")
        self._compiler_flags.append("-fno-optimize-sibling-calls")

    @property
    def name(self) -> str:
        return "GNU_AVR_5"

    @property
    def segment_alignment(self) -> int:
        return 2

    def _get_assembler_target(self, processor: ArchInfo) -> str:
        if processor.isa is not InstructionSet.AVR:
            raise ValueError(
                f"The GNU AVR toolchain does not support ISAs which are not AVR; "
                f"given ISA {processor.isa.name}"
            )
        if self._config.assembler_target:
            return self._config.assembler_target
        return InstructionSet.AVR.value.lower()
