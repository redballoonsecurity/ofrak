from abc import ABC, abstractmethod
from typing import Dict, Tuple

from ofrak_patch_maker.toolchain.model import BinFileType, Segment
from ofrak_type.symbol_type import LinkableSymbolType


class AbstractBinaryFileParser(ABC):
    @property
    @abstractmethod
    def file_format(self) -> BinFileType:
        raise NotImplementedError()

    @abstractmethod
    def parse_symbols(self, tool_output: str) -> Dict[str, Tuple[int, LinkableSymbolType]]:
        raise NotImplementedError()

    @abstractmethod
    def parse_sections(self, tool_output: str) -> Tuple[Segment, ...]:
        raise NotImplementedError()

    @abstractmethod
    def parse_relocations(self, tool_output: str) -> Dict[str, Tuple[int, LinkableSymbolType]]:
        raise NotImplementedError()
