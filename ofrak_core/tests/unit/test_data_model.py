"""
This module tests the data model components of the OFRAK framework.
"""
from ofrak_type.range import Range

from ofrak.model.data_model import DataPatch


def test_data_patch_repr(capsys):
    """
    Tests the string representation of a DataPatch object.

    This test verifies that the DataPatch object correctly formats its string representation
    when printed, showing the patch data, range, and size.
    - Creates a DataPatch with specific byte data and range
    - Verifies that the string representation matches the expected format
    """
    data_patch = DataPatch(Range(0x100, 0x101), b"\xfe\xed\xfa\xce", b"\xff")
    print(data_patch, end="")
    out, _ = capsys.readouterr()
    assert out == "DataPatch(feedface, Range(0x100, 0x101), 1)"
