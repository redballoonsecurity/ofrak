import io

import pytest
from ofrak_io.deserializer import BinaryDeserializer, DeserializationError

from ofrak_type.endianness import Endianness


class TestBinaryDeserializer:
    def test_set_stream(self):
        message = b"hello"
        deserializer = BinaryDeserializer()
        deserializer.set_stream(io.BytesIO(message))
        deserialized = deserializer.read(len(message))
        assert deserialized == message

    def test_set_endianness(self):
        deserializer = BinaryDeserializer(io.BytesIO())
        deserializer.set_endianness(Endianness.LITTLE_ENDIAN)

    def test_set_word_size(self):
        deserializer = BinaryDeserializer(io.BytesIO())
        assert deserializer.get_word_size() == 8
        deserializer.set_word_size(4)
        assert deserializer.get_word_size() == 4

    def test_seek(self):
        message = b"HelloWorld"
        deserializer = BinaryDeserializer(io.BytesIO(message))
        assert deserializer.position() == 0
        deserializer.seek(len(b"Hello"))
        assert deserializer.position() == len(b"Hello")
        assert deserializer.read(len(b"World")) == b"World"
        deserializer.seek(0)
        assert deserializer.position() == 0
        assert deserializer.read(len(b"Hello")) == b"Hello"
        assert deserializer.position() == len(b"World")

    def test_seek_error(self):
        deserializer = BinaryDeserializer()
        with pytest.raises(DeserializationError):
            deserializer.seek(5)

    def test_position_error(self):
        deserializer = BinaryDeserializer()
        with pytest.raises(DeserializationError):
            deserializer.position()

    def test_read_error(self):
        deserializer = BinaryDeserializer()
        with pytest.raises(DeserializationError):
            deserializer.read(5)

    def test_read_length_error(self):
        deserializer = BinaryDeserializer(io.BytesIO(b""))
        with pytest.raises(DeserializationError):
            deserializer.read(10)
