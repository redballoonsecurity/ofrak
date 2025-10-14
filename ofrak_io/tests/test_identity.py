"""
This module tests the identity property of binary serialization and deserialization operations.
"""
import io
import os
import random
import string
from dataclasses import dataclass

from hypothesis import given, strategies
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_io.serializer import BinarySerializer

ubyte_strategy = strategies.integers(min_value=0, max_value=2**8 - 1)
uint16_strategy = strategies.integers(min_value=0, max_value=2**16 - 1)
uint32_strategy = strategies.integers(min_value=0, max_value=2**32 - 1)
uint64_strategy = strategies.integers(min_value=0, max_value=2**64 - 1)

signed_byte_strategy = strategies.integers(min_value=-(2**7), max_value=2**7 - 1)
signed_int16_strategy = strategies.integers(min_value=-(2**15), max_value=2**15 - 1)
signed_int32_strategy = strategies.integers(min_value=-(2**31), max_value=2**31 - 1)
signed_int64_strategy = strategies.integers(min_value=-(2**63), max_value=2**63 - 1)
long_long_strategy = strategies.integers(min_value=-(2**63), max_value=2**63 - 1)
float_strategy = strategies.floats(width=32, allow_nan=False)
double_float_strategy = strategies.floats(width=64, allow_nan=False)
string_strategy = strategies.text(alphabet=string.printable)


@dataclass
class PackMultipleValues:
    i_value: int
    b_value: int
    q_value: int

    @property
    def char(self):
        return "IBQ"


pack_multiple_strategy = strategies.builds(
    PackMultipleValues, uint16_strategy, ubyte_strategy, uint32_strategy
)


class TestBinarySerializationIdentity:
    """
    Test that serializing a value with the `BinarySerializer`, and then deserializing with the
    `BinaryDeserializer` produces the same value ("identity" test).
    """

    @given(values=pack_multiple_strategy)
    def test_multiple(self, values: PackMultipleValues):
        """
        Test the identity property for packing and unpacking multiple values at once.

        This test verifies that:
        - A set of values (int, byte, and quad) are serialized together
        - The serialized data is then deserialized back into the same values
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        serializer.pack_multiple(values.char, values.i_value, values.b_value, values.q_value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_multiple(values.char)
        assert PackMultipleValues(*deserialized) == values

    @given(values=pack_multiple_strategy)
    def test_multiple_auto_bitwidth(self, values: PackMultipleValues):
        """
        Test the identity property for packing and unpacking multiple values with auto bitwidth detection.

        This test verifies that:
        - A set of values (int, byte, and quad) are serialized with auto bitwidth detection
        - The serialized data is then deserialized back into the same values using auto bitwidth
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer, word_size=4)
        serializer.pack_multiple(
            values.char, values.i_value, values.b_value, values.q_value, auto_bitwidth=True
        )
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized), word_size=4)
        deserialized = deserializer.unpack_multiple(values.char, auto_bitwidth=True)
        assert PackMultipleValues(*deserialized) == values

    @given(value=ubyte_strategy)
    def test_ubyte(self, value: int):
        """
        Test the identity property for unsigned byte serialization and deserialization.

        This test verifies that:
        - An unsigned byte value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_ubyte(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_ubyte()
        assert deserialized == value

    @given(value=uint16_strategy)
    def test_ushort(self, value: int):
        """
        Test the identity property for unsigned short serialization and deserialization.

        This test verifies that:
        - An unsigned short value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_ushort(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_ushort()
        assert deserialized == value

    @given(value=uint32_strategy)
    def test_uint(self, value: int):
        """
        Test the identity property for unsigned integer serialization and deserialization.

        This test verifies that:
        - An unsigned integer value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_uint(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_uint()
        assert deserialized == value

    @given(value=uint64_strategy)
    def test_ulong(self, value: int):
        """
        Test the identity property for unsigned long serialization and deserialization.

        This test verifies that:
        - An unsigned long value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_ulong(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_ulong()
        assert deserialized == value

    @given(value=signed_byte_strategy)
    def test_byte(self, value: int):
        """
        Test the identity property for signed byte serialization and deserialization.

        This test verifies that:
        - A signed byte value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_byte(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_byte()
        assert deserialized == value

    @given(value=signed_int16_strategy)
    def test_short(self, value: int):
        """
        Test the identity property for signed short serialization and deserialization.

        This test verifies that:
        - A signed short value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_short(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_short()
        assert deserialized == value

    @given(value=signed_int32_strategy)
    def test_int(self, value: int):
        """
        Test the identity property for signed integer serialization and deserialization.

        This test verifies that:
        - A signed integer value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_int(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_int()
        assert deserialized == value

    @given(value=signed_int64_strategy)
    def test_long(self, value: int):
        """
        Test the identity property for signed long serialization and deserialization.

        This test verifies that:
        - A signed long value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_long(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_long()
        assert deserialized == value

    @given(value=long_long_strategy)
    def test_long_long(self, value: int):
        """
        Test the identity property for long long serialization and deserialization.

        This test verifies that:
        - A long long value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_long_long(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_long_long()
        assert deserialized == value

    @given(value=float_strategy)
    def test_float(self, value: float):
        """
        Test the identity property for float serialization and deserialization.

        This test verifies that:
        - A float value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        serializer.pack_float(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_float()
        assert deserialized == value

    @given(value=double_float_strategy)
    def test_double(self, value: float):
        """
        Test the identity property for double serialization and deserialization.

        This test verifies that:
        - A double value is serialized
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        serializer.pack_double(value)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_double()
        assert deserialized == value

    @given(value=string_strategy)
    def test_string(self, value: str):
        """
        Test the identity property for string serialization and deserialization.

        This test verifies that:
        - A string value is serialized with a specified length
        - The serialized data is then deserialized back to the same value
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        string_length = len(value) + random.randint(0, 4)
        serializer.pack_string(value, string_length)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_string(len(value))
        assert deserialized == value

    def test_variable_length_string(self):
        """
        Test the identity property for variable-length string serialization and deserialization.

        This test verifies that:
        - A string is serialized with a fixed length
        - The serialized data is then deserialized back to the same value using automatic length detection
        """
        string_text = "hello"
        string_length = len(string_text) + 10
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        serializer.pack_string(string_text, string_length)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_string()
        assert deserialized == string_text

    @given(value=ubyte_strategy)
    def test_dynamic_bytes(self, value: int):
        """
        Test the identity property for dynamic bytes serialization and deserialization.

        This test verifies that:
        - A random byte sequence is serialized
        - The serialized data is then deserialized back to the same byte sequence
        """
        raw_bytes = os.urandom(value)
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_dynamic_bytes(raw_bytes)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_dynamic_bytes()
        assert deserialized == raw_bytes

    @given(value=uint16_strategy)
    def test_dynamic_bytes_short(self, value: int):
        """
        Test the identity property for dynamic bytes serialization and deserialization with short length.

        This test verifies that:
        - A random byte sequence is serialized with a short length prefix
        - The serialized data is then deserialized back to the same byte sequence
        """
        raw_bytes = os.urandom(value)
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)

        serializer.pack_dynamic_bytes_short(raw_bytes)
        serialized = buffer.getvalue()

        deserializer = BinaryDeserializer(io.BytesIO(serialized))
        deserialized = deserializer.unpack_dynamic_bytes_short()
        assert deserialized == raw_bytes
