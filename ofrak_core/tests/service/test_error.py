from ofrak.service.error import SerializedError


def test_serialized_error():
    error = SerializedError("Something went wrong")
    serialized = error.to_json()
    deserialized = SerializedError.from_json(serialized)
    assert str(error) == str(deserialized)
