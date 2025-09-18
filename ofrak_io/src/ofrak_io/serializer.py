import struct
from typing import Any, BinaryIO, Union, Optional

from ofrak_type.endianness import Endianness


class SerializationError(Exception):
    pass


class BinarySerializer:
    def __init__(
        self,
        writer: Optional[BinaryIO] = None,
        endianness: Endianness = Endianness.BIG_ENDIAN,
        word_size: int = 8,
    ):
        self._writer = writer
        self._endianness = endianness
        self._word_size = word_size
        self._initial_position = 0 if writer is None else writer.tell()

    def set_stream(
        self,
        writer: BinaryIO,
        endianness: Endianness = Endianness.BIG_ENDIAN,
        word_size: int = 8,
    ):
        self._writer = writer
        self._endianness = endianness
        self._word_size = word_size
        self._initial_position = writer.tell()

    def set_endianness(self, endianness: Endianness) -> None:
        self._endianness = endianness

    def set_word_size(self, word_size: int) -> None:
        self._word_size = word_size

    def get_word_size(self) -> int:
        return self._word_size

    def seek(self, position: int) -> int:
        if self._writer is None:
            raise SerializationError("writer is not set")
        return self._writer.seek(self._initial_position + position)

    def position(self) -> int:
        if self._writer is None:
            raise SerializationError("writer is not set")
        return self._writer.tell()

    def write(self, data: bytes) -> int:
        if self._writer is None:
            raise SerializationError("writer is not set")
        length = self._writer.write(data)
        if len(data) != length:
            raise SerializationError(f"Could not write {len(data)} bytes")
        return length

    def pack_multiple(self, char: str, *values: Any, auto_bitwidth: bool = False) -> None:
        char = self._endianness.get_struct_flag() + char
        if auto_bitwidth and self._word_size != 8:
            char = char.replace("Q", "I").replace("q", "i")
        self.write(struct.pack(char, *values))

    def _pack(self, char: str, value: Union[int, float]) -> None:
        char = self._endianness.get_struct_flag() + char
        self.write(struct.pack(char, value))

    def pack_ubyte(self, value: int) -> None:
        self._pack("B", value)

    def pack_ushort(self, value: int) -> None:
        self._pack("H", value)

    def pack_uint(self, value: int) -> None:
        self._pack("I", value)

    def pack_ulong(self, value: int) -> None:
        char = "I" if self._word_size == 4 else "Q"
        self._pack(char, value)

    def pack_byte(self, value: int) -> None:
        self._pack("b", value)

    def pack_short(self, value: int) -> None:
        self._pack("h", value)

    def pack_int(self, value: int) -> None:
        self._pack("i", value)

    def pack_long(self, value: int) -> None:
        char = "i" if self._word_size == 4 else "q"
        self._pack(char, value)

    def pack_long_long(self, value: int) -> None:
        self._pack("q", value)

    def pack_float(self, value: float) -> None:
        self._pack("f", value)

    def pack_double(self, value: float) -> None:
        self._pack("d", value)

    def pack_string(self, value: str, length: int) -> None:
        value_raw = value.encode("utf-8")
        if len(value_raw) > length:
            raise SerializationError(f"The provided string does not fit in {length} bytes")
        self.write(value_raw.ljust(length, b"\x00"))

    def pack_dynamic_bytes(self, value: bytes) -> None:
        self.pack_ubyte(len(value))
        self.write(value)

    def pack_dynamic_bytes_short(self, value: bytes) -> None:
        self.pack_ushort(len(value))
        self.write(value)
