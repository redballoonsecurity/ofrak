from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_patch_maker.toolchain.gnu import GNU_10_Toolchain
from ofrak_patch_maker.binary_parser.gnu import GNU_V10_ELF_Parser
from ofrak_patch_maker.toolchain.model import ToolchainConfig
from ofrak_type.architecture import InstructionSet, SubInstructionSet, ArchInfo
import logging
from typing import Tuple


class GNU_AARCH64_LINUX_10_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_V10_ELF_Parser()]

    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)
        # Enable compilation of the GNU atomics intrinsics.
        self._compiler_flags.append("-mno-outline-atomics")
        # Force literal pools at end of functions, rather than .rodata
        self._compiler_flags.append("-mpc-relative-literal-loads")

    @property
    def name(self) -> str:
        return "GNU_AARCH64_LINUX_10"

    @property
    def segment_alignment(self) -> int:
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

    def _get_assembler_target(self, processor: ArchInfo):
        if processor.isa is not InstructionSet.AARCH64:
            raise ValueError(
                f"The GNU AARCH64 toolchain does not support ISAs which are not AARCH64; "
                f"given ISA {processor.isa.name}"
            )
        if processor.sub_isa is not None:
            return processor.sub_isa.value.lower()
        return SubInstructionSet.ARMv8A.value.lower()
