import re
from typing import Set, Tuple, Dict

from ofrak_patch_maker.binary_parser.abstract import AbstractBinaryFileParser
from ofrak_patch_maker.toolchain.model import BinFileType, Segment
from ofrak_type.memory_permissions import MemoryPermissions


class GNU_ELF_Parser(AbstractBinaryFileParser):
    file_format = BinFileType.ELF

    _re_symbol_prog = re.compile(
        r"^(?P<address>[0-9A-Fa-f]{8})[ \t]+"
        r"(?P<flags>[lg!\s][w\s][C\s][W\s][I\s][dD\s][fFO\s])?[ \t]+"
        r"(?P<section>\S+)[ \t]"
        r"(?P<size_or_alignment>[0-9A-Fa-f]{8})[ \t]*"
        r"(?P<name>.+)?$",
        flags=re.MULTILINE,
    )
    _re_section_prog = re.compile(
        r"^[\s|\t]*"
        r"(?P<idx>[0-9]+)[ \t]+"
        r"(?P<name>\S+)[ \t]+"
        r"(?P<size>[0-9A-Fa-f]+)[ \t]+"
        r"(?P<vma>[0-9A-Fa-f]+)[ \t]+"
        r"(?P<lma>[0-9A-Fa-f]+)[ \t]+"
        r"(?P<offset>[0-9A-Fa-f]+)[ \t]+"
        r"(?P<alignment>[0-9]\*\*[0-9])\n[ \n]+"
        r"(?P<flags>[\S, ]+)",
        flags=re.MULTILINE,
    )

    def parse_symbols(self, output: str) -> Dict[str, int]:
        """
        Use `objdump` with the `--syms` flag to get info on all defined symbols in a file. Parses
        columns based on: <https://stackoverflow.com/a/16471895/16690095>.
        """
        result = {}
        symbols = self._get_all_symbols(output)
        for symbol in symbols:
            if symbol[2] != "*UND*":
                result[symbol[0]] = symbol[1]
        return result

    def parse_sections(self, output: str) -> Tuple[Segment, ...]:
        """
        Uses `objdump` with the `--section-headers` flag to get info on all symbols in a file.
        Parses the returned columns.
        """
        segments = []
        for section_data in self._re_section_prog.finditer(output):
            # Default permissions are RW, then -R/+X as appropriate
            permissions = MemoryPermissions.RW
            if "READONLY" in section_data.group("flags"):
                permissions = permissions - MemoryPermissions.W
            if "CODE" in section_data.group("flags"):
                permissions = permissions + MemoryPermissions.X
            # TODO: Figure out how to infer this.
            is_entry = False
            seg = Segment(
                segment_name=section_data.group("name"),
                vm_address=int(section_data.group("vma"), 16),
                offset=int(section_data.group("offset"), 16),
                is_entry=is_entry,
                length=int(section_data.group("size"), 16),
                access_perms=permissions,
            )
            segments.append(seg)
        return tuple(segments)

    def parse_relocations(self, output: str) -> Dict[str, int]:
        """
        Use `objdump` with the `--syms` flag to get info on all undefined symbols in a file. Parses
        columns based on: <https://stackoverflow.com/a/16471895/16690095>.
        """
        result = {}
        symbols = self._get_all_symbols(output)
        for symbol in symbols:
            if symbol[2] == "*UND*":
                result[symbol[0]] = symbol[1]
        return result

    def _get_all_symbols(self, output: str) -> Set[Tuple[str, int, str]]:
        result = set()
        for symbol_data in self._re_symbol_prog.finditer(output):
            name = symbol_data.group("name")
            addr = symbol_data.group("address")
            symbol_section = symbol_data.group("section")

            if name and addr:
                result.add((name, int(addr, 16), symbol_section))
        return result


class GNU_V10_ELF_Parser(GNU_ELF_Parser):
    file_format = BinFileType.ELF

    def parse_symbols(self, tool_output: str) -> Dict[str, int]:
        symbols = {}
        lines = tool_output.split("\n")
        for l in lines:
            tokens = l.split()
            if "O" in tokens or "F" in tokens:
                symbols.update({tokens[-1]: int(tokens[0], 16)})
        return symbols
