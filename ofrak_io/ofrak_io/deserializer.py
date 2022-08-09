import struct
from typing import cast, Union, Tuple, BinaryIO, Optional

from ofrak_type.endianness import Endianness


class DeserializationError(Exception):
    pass


class BinaryDeserializer:
    def __init__(
        self,
        reader: Optional[BinaryIO] = None,
        endianness: Endianness = Endianness.BIG_ENDIAN,
        word_size: int = 8,
    ):
        self._reader = reader
        self._endianness = endianness
        self._word_size = word_size
        self._initial_position = 0 if reader is None else reader.tell()

    def set_stream(
        self,
        reader: BinaryIO,
        endianness: Endianness = Endianness.BIG_ENDIAN,
        word_size: int = 8,
    ):
        self._reader = reader
        self._endianness = endianness
        self._word_size = word_size
        self._initial_position = reader.tell()

    def set_endianness(self, endianness: Endianness) -> None:
        self._endianness = endianness

    def set_word_size(self, word_size: int) -> None:
        self._word_size = word_size

    def get_word_size(self) -> int:
        return self._word_size

    def seek(self, position: int) -> int:
        if self._reader is None:
            raise DeserializationError("reader is not set")
        return self._reader.seek(self._initial_position + position)

    def position(self) -> int:
        if self._reader is None:
            raise DeserializationError("reader is not set")
        return self._reader.tell()

    def read(self, length: int) -> bytes:
        if self._reader is None:
            raise DeserializationError("reader is not set")
        data = self._reader.read(length)
        if len(data) != length:
            raise DeserializationError(f"Could not read {length} bytes, data len is {len(data)}")
        return data

    def unpack_multiple(self, char: str, length: int = -1, auto_bitwidth: bool = False) -> Tuple:
        char = self._endianness.get_struct_flag() + char
        if auto_bitwidth and self._word_size != 8:
            char = char.replace("Q", "I").replace("q", "i")
        if length <= 0:
            length = struct.calcsize(char)
        return struct.unpack(char, self.read(length))

    def _unpack(self, char: str, length: int) -> Union[int, float]:
        char = self._endianness.get_struct_flag() + char
        (result,) = struct.unpack(char, self.read(length))
        return result

    def unpack_ubyte(self) -> int:
        return cast(int, self._unpack("B", 1))

    def unpack_ushort(self) -> int:
        return cast(int, self._unpack("H", 2))

    def unpack_uint(self) -> int:
        return cast(int, self._unpack("I", 4))

    def unpack_ulong(self) -> int:
        char = "I" if self._word_size == 4 else "Q"
        return cast(int, self._unpack(char, self._word_size))

    def unpack_byte(self) -> int:
        return cast(int, self._unpack("b", 1))

    def unpack_short(self) -> int:
        return cast(int, self._unpack("h", 2))

    def unpack_int(self) -> int:
        return cast(int, self._unpack("i", 4))

    def unpack_long(self) -> int:
        char = "i" if self._word_size == 4 else "q"
        return cast(int, self._unpack(char, self._word_size))

    def unpack_long_long(self) -> int:
        return cast(int, self._unpack("q", 8))

    def unpack_float(self) -> float:
        return cast(float, self._unpack("f", 4))

    def unpack_double(self) -> float:
        return cast(float, self._unpack("d", 8))

    def unpack_string(self, length: int = -1) -> str:
        if length < 0:
            current_string = []
            while True:
                current_char = self.read(1)
                if current_char == b"\x00":
                    break
                else:
                    current_string.append(current_char.decode("utf-8"))
            value = "".join(current_string)
        else:
            value = self.read(length).replace(b"\x00", b"").decode("utf-8")
        return value

    def unpack_dynamic_bytes(self) -> bytes:
        length = self.unpack_ubyte()
        return self.read(length)

    def unpack_dynamic_bytes_short(self) -> bytes:
        length = self.unpack_ushort()
        return self.read(length)
