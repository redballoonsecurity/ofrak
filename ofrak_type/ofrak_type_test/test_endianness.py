import pytest

from ofrak_type.endianness import Endianness


@pytest.mark.parametrize(
    "endianness,expected_struct_flag",
    [
        (Endianness.BIG_ENDIAN, ">"),
        (Endianness.LITTLE_ENDIAN, "<"),
    ],
)
def test_endianness_get_struct_flag(endianness: Endianness, expected_struct_flag: str):
    assert endianness.get_struct_flag() == expected_struct_flag
