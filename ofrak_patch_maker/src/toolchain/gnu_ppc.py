import logging
from typing import Optional

from ofrak_patch_maker.binary_parser.gnu import GNU_V10_ELF_Parser
from ofrak_patch_maker.toolchain.gnu import GNU_10_Toolchain
from ofrak_patch_maker.toolchain.model import ToolchainConfig
from ofrak_type import ArchInfo, InstructionSet, MemoryPermissions


class GNU_PPC_LINUX_10_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_V10_ELF_Parser()]

    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        if self._config.hard_float:
            self._compiler_flags.append("-mhard-float")
        else:
            self._compiler_flags.append("-msoft-float")

    @property
    def segment_alignment(self) -> int:
        return 4  # TODO: Check

    @property
    def name(self) -> str:
        return "GNU_PPC_LINUX_10"

    def _get_assembler_target(self, processor: ArchInfo) -> Optional[str]:
        if processor.isa != InstructionSet.PPC:
            raise ValueError(
                f"The GNU PPC toolchain does not support ISAs that are not PPC. "
                f"(Got: {processor.isa.name}.)"
            )
        if self._config.assembler_target:
            return self._config.assembler_target

        # PPC GNU 10 does not implement -march. See:
        # https://gcc.gnu.org/onlinedocs/gcc-10.4.0/gcc/RS_002f6000-and-PowerPC-Options.html#RS_002f6000-and-PowerPC-Options
        return None

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

    @staticmethod
    def _ld_generate_got_plt_section(
        memory_region_name: str,
    ) -> str:
        got_plt_section_name = ".got2"
        return (
            f"    {got_plt_section_name} : {{\n"
            f"        *.o({got_plt_section_name})\n"
            f"    }} > {memory_region_name}"
        )

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
