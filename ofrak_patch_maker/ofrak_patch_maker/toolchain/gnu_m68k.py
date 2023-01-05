from typing import Tuple

from ofrak_type.memory_permissions import MemoryPermissions

from ofrak_type.architecture import InstructionSet, ArchInfo
from ofrak_patch_maker.toolchain.gnu import GNU_10_Toolchain
from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser
from ofrak_patch_maker.toolchain.model import ToolchainConfig
import logging


class GNU_M68K_LINUX_10_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_ELF_Parser()]

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
        return "GNU_M68K_LINUX_10"

    @property
    def segment_alignment(self) -> int:
        return 4

    def _get_assembler_target(self, processor: ArchInfo):
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
