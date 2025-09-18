import io

import pytest
from ofrak_io.serializer import BinarySerializer, SerializationError

from ofrak_type.endianness import Endianness


class TestBinarySerializer:
    def test_set_stream(self):
        buffer = io.BytesIO()
        serializer = BinarySerializer()
        serializer.set_stream(buffer)
        serializer.write(b"hello")
        assert buffer.getvalue() == b"hello"

    def test_set_endianness(self):
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        serializer.set_endianness(Endianness.LITTLE_ENDIAN)

    def test_set_word_size(self):
        serializer = BinarySerializer(io.BytesIO())
        assert serializer.get_word_size() == 8
        serializer.set_word_size(4)
        assert serializer.get_word_size() == 4

    def test_seek(self):
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        assert serializer.position() == 0
        serializer.write(b"Hello")
        assert serializer.position() == len(b"Hello")
        assert buffer.getvalue() == b"Hello"
        serializer.seek(0)
        assert serializer.position() == 0
        serializer.write(b"world")
        assert serializer.position() == len(b"world")
        assert buffer.getvalue() == b"world"

    def test_seek_writer_not_set_error(self):
        serializer = BinarySerializer()
        with pytest.raises(SerializationError):
            serializer.seek(5)

    def test_position_writer_not_set_error(self):
        serializer = BinarySerializer()
        with pytest.raises(SerializationError):
            serializer.position()

    def test_write_error_writer_not_set(self):
        serializer = BinarySerializer()
        with pytest.raises(SerializationError):
            serializer.write(b"hello")

    def test_write_error_length(self):
        class OffByOneBuffer(io.BytesIO):
            pass

            def write(self, *args, **kwargs):  # real signature unknown
                first_arg = args[0]
                return len(first_arg) + 1

        buffer = OffByOneBuffer()
        serializer = BinarySerializer(buffer)
        with pytest.raises(SerializationError):
            serializer.write(b"hello")

    def test_pack_string_error(self):
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        string_value = "hello"
        with pytest.raises(SerializationError):
            serializer.pack_string(string_value, len(string_value) - 1)
