"""
Test error handling in OFRAK.
"""
from ofrak.service.error import SerializedError


def test_serialized_error():
    """
    Test error serialization.

    This test verifies that:
    - An error can be serialized to json.
    - The json can then be desirialized.
    - The original error matches the serialized-deserialized one
    """
    error = SerializedError("Something went wrong")
    serialized = error.to_json()
    deserialized = SerializedError.from_json(serialized)
    assert str(error) == str(deserialized)
