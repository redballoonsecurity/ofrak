from ofrak_patch_maker.toolchain.gnu import GNU_10_Toolchain
from ofrak_patch_maker.binary_parser.gnu import GNU_V10_ELF_Parser
from ofrak_patch_maker.toolchain.model import ToolchainConfig
import logging

from ofrak_type.architecture import ArchInfo


class GNU_X86_64_LINUX_EABI_10_3_0_Toolchain(GNU_10_Toolchain):
    binary_file_parsers = [GNU_V10_ELF_Parser()]

    def __init__(
        self,
        processor: ArchInfo,
        toolchain_config: ToolchainConfig,
        logger: logging.Logger = logging.getLogger(__name__),
    ):
        super().__init__(processor, toolchain_config, logger=logger)

        self._compiler_flags.extend(
            [
                "-malign-data=abi",  # further relaxes compiler data alignment policy
                "-mno-sse2",  # restricts usage of xmm register / avx instruction usage.
            ]
        )

        if not self._config.hard_float:
            self._compiler_flags.append("-msoft-float")

    @property
    def name(self) -> str:
        return "GNU_X86_64_LINUX_EABI_10_3_0"

    @property
    def segment_alignment(self) -> int:
        return 16

    def _get_assembler_target(self, processor: ArchInfo):
        if self._config.assembler_target:
            return self._config.assembler_target
        return "generic64"

    @staticmethod
    def ld_generate_bss_section(
        memory_region_name: str,
    ) -> str:
        """
        We override this for x64 so we can provide SUBALIGN(1)
        This is required to correctly estimate how much size we need for bss
        when splitting up data structures into their own individual bss sections.
        If we were to let the linker align every structure's section to 8 or 16, it would
        insert empty space that we had not allocated for the bss memory region.
        gcc/ld do prefer 8 alignment for data if you don't force this, but it is not likely to be
        hugely faster on recent hardware for most situations (ie not locked instructions
        across a cache line):
        https://lemire.me/blog/2012/05/31/data-alignment-for-speed-myth-or-reality/
        Pre-2011 x64 chips might be slower with these kinds of accesses, but:
           - We should not bend over backwards for processors we've not evaluated yet.
           - .bss handling is already difficult enough as is.
           - The flexibility granted by this feature likely justifies a relatively small performance impact.
        We should address this as a problem if future users find that performance is noticeably/severely impacted.
        """
        bss_section_name = ".bss"
        return (
            f"    {bss_section_name} : SUBALIGN(1) {{\n"
            f"        *.o({bss_section_name}, {bss_section_name}.*)\n"
            f"    }} > {memory_region_name}"
        )
