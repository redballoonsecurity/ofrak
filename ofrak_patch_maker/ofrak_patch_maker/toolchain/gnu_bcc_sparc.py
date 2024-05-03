from typing import Optional

from ofrak_patch_maker.binary_parser.gnu import GNU_ELF_Parser
from ofrak_patch_maker.toolchain.gnu import Abstract_GNU_Toolchain
from ofrak_type import ArchInfo


class GNU_BCC_SPARC_Toolchain(Abstract_GNU_Toolchain):
    binary_file_parsers = [GNU_ELF_Parser()]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._linker_flags.remove("--no-dynamic-linker")

    @property
    def segment_alignment(self) -> int:
        # No specific segment alignment called out in the compiler manual, but
        # we'll leave this here just to be safe
        return 4

    @property
    def name(self) -> str:
        return "BCC_SPARC_GAISLER_ELF"

    def _get_assembler_target(self, processor: ArchInfo) -> Optional[str]:
        if self._config.assembler_target:
            return self._config.assembler_target
        return None

    def _get_compiler_target(self, processor: ArchInfo) -> Optional[str]:
        if self._config.compiler_target:
            return self._config.compiler_target
        return processor.isa.value.lower()

    def linker_include_filter(self, symbol_name: str) -> bool:
        return "_DYNAMIC" in symbol_name
