"""
Test the tag model functionality.
"""
from ofrak.core import GenericBinary


def test_tag_model_repr(capsys):
    """
    Test the string representation of the tag model.

    This test verifies that:
    - The GenericBinary tag can be printed as a string
    - The output matches the expected string representation
    """
    print(GenericBinary, end="")
    out, _ = capsys.readouterr()
    assert out == "GenericBinary"
