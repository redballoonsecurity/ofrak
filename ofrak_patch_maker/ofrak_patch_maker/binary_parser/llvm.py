import re
from abc import ABC
from typing import Tuple, Dict, List, Union

from ofrak_patch_maker.binary_parser.abstract import AbstractBinaryFileParser
from ofrak_patch_maker.toolchain.model import BinFileType, Segment, ToolchainException
from ofrak_type.memory_permissions import MemoryPermissions


class Abstract_LLVM_Readobj_Parser(AbstractBinaryFileParser, ABC):
    def _parse_readobj_sections(
        self, output: str, section_keys: Dict[str, str], flag_key: str
    ) -> Tuple[Segment, ...]:
        sections = []

        while "Section {" in output:
            start_idx = output.index("Section {")
            end_idx = output.index("}", start_idx)

            section_text = output[start_idx : end_idx + 1]
            section_lines = section_text.split("\n")[1:-1]

            section = self._parse_readobj_section(section_lines, section_keys, flag_key)
            sections.append(section)

            output = output[end_idx:]

        return tuple(sections)

    @staticmethod
    def _parse_readobj_section(lines: List[str], keys: Dict[str, str], flag_key: str) -> Segment:
        remaining_keys = {k: keys[k] for k in keys}
        kvs: Dict[str, Union[str, int, bool, MemoryPermissions]] = {}

        for line in lines:
            line = line.strip()

            if line.startswith(flag_key):
                flags_str = line[
                    line.index("(") + 1 : line.index(")")
                ]  # Assumes the line is formatted correctly.
                flags = int(
                    flags_str, 0
                )  # We want to raise a ValueError here if the int conversion fails.

                # TODO: Flags (attributes) in Mach-O don't provide full permissions of the section
                #  Assumptions:
                #  - Bitfields remain the same across file formats
                #  - Every section in an input is readable
                if flags & 5 == 5:
                    kvs[remaining_keys[flag_key]] = MemoryPermissions.RWX
                elif flags & 4 == 4:
                    kvs[remaining_keys[flag_key]] = MemoryPermissions.RX
                elif flags & 1 == 1:
                    kvs[remaining_keys[flag_key]] = MemoryPermissions.RW
                else:
                    kvs[remaining_keys[flag_key]] = MemoryPermissions.R

                del remaining_keys[flag_key]

            elif ": " in line:
                key, value = tuple(line.strip().split(": "))

                if key in remaining_keys:
                    # Only take the value text until the first whitespace.
                    value = value.split(" ")[0]

                    # Try to convert the value to an integer.
                    try:
                        value = int(value, 0)  # type: ignore
                    except ValueError:
                        pass

                    kvs[remaining_keys[key]] = value
                    del remaining_keys[key]

                    if len(remaining_keys) == 0:
                        break

        if len(remaining_keys) > 0:
            raise ToolchainException("Could not parse all keys!")

        # TODO: Figure out how to infer this.
        kvs["is_entry"] = False

        return Segment(**kvs)  # type: ignore


class LLVM_ELF_Parser(Abstract_LLVM_Readobj_Parser):
    file_format = BinFileType.ELF

    _re_symbol_prog = re.compile(r"(?<=Symbol ){((\s|\S)+?)}")
    _re_name_prog = re.compile(r"(?<=Name: )(\S+)")
    _re_value_prog = re.compile(r"(?<=Value: 0x)(\S+)")
    _re_sym_section_prog = re.compile(r"(?<=Section: )(\S+)")

    def parse_sections(self, output: str) -> Tuple[Segment, ...]:
        section_keys = {
            "Name": "segment_name",
            "Address": "vm_address",
            "Offset": "offset",
            "Size": "length",
            "Flags": "access_perms",
        }

        return self._parse_readobj_sections(output, section_keys, "Flags")

    def parse_symbols(self, readobj_out: str) -> Dict[str, int]:
        result = {}
        symbol_data = [x[0] for x in self._re_symbol_prog.findall(readobj_out)]
        for s in symbol_data:
            name = self._re_name_prog.search(s)
            addr_value = self._re_value_prog.search(s)
            symbol_section = self._re_sym_section_prog.search(s)
            if name and addr_value:
                if symbol_section and symbol_section.group(0) != "Undefined":
                    result.update({name.group(0): int(addr_value.group(0), 16)})
        return result


class LLVM_MACH_O_Parser(Abstract_LLVM_Readobj_Parser):
    file_format = BinFileType.MACH_O

    def parse_sections(self, output: str) -> Tuple[Segment, ...]:
        section_keys = {
            "Name": "segment_name",
            "Address": "vm_address",
            "Offset": "offset",
            "Size": "length",
            "Attributes": "access_perms",
        }

        return self._parse_readobj_sections(output, section_keys, "Attributes")

    def parse_symbols(self, output: str) -> Dict[str, int]:
        raise NotImplementedError()
