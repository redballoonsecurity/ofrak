"""
Test the BitWidth enum and its methods.
"""
import pytest

from ofrak_type.bit_width import BitWidth


@pytest.mark.parametrize(
    "bitwidth,expected_word_size",
    [(BitWidth.BIT_8, 1), (BitWidth.BIT_16, 2), (BitWidth.BIT_32, 4), (BitWidth.BIT_64, 8)],
)
def test_bitwidth_get_word_size(bitwidth: BitWidth, expected_word_size: int):
    """
    Test that the get_word_size method of BitWidth returns the correct word size for each possible
    bit width.
    """
    assert bitwidth.get_word_size() == expected_word_size
