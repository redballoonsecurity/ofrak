"""
This module tests the endianness functionality.
"""
import pytest
import struct

from ofrak_type.endianness import Endianness


@pytest.mark.parametrize(
    "endianness,expected_struct_flag",
    [
        (Endianness.BIG_ENDIAN, ">"),
        (Endianness.LITTLE_ENDIAN, "<"),
    ],
)
def test_endianness_get_struct_flag(endianness: Endianness, expected_struct_flag: str):
    """
    This test verifies that the Endianness enum correctly returns the appropriate struct flag
    for packing and unpacking binary data.

    This test verifies that:
    - The get_struct_flag() method returns the correct struct module flag
    - The returned flag can be used with struct.pack/unpack to correctly encode/decode values
    - The endianness behavior is correctly reflected in the packed byte order
    """
    assert endianness.get_struct_flag() == expected_struct_flag

    # Test the struct flag actually works with struct module
    test_value = 0x1234
    packed = struct.pack(f"{expected_struct_flag}H", test_value)
    unpacked = struct.unpack(f"{expected_struct_flag}H", packed)[0]
    assert unpacked == test_value

    # Verify endianness behavior
    if endianness == Endianness.BIG_ENDIAN:
        assert packed == b"\x12\x34"
    elif endianness == Endianness.LITTLE_ENDIAN:
        assert packed == b"\x34\x12"
