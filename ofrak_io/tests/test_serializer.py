"""
Test the functionality of the BinarySerializer class.
"""
import io

import pytest
from ofrak_io.serializer import BinarySerializer, SerializationError

from ofrak_type.endianness import Endianness


class TestBinarySerializer:
    def test_set_stream(self):
        """
        This test verifies that the serializer can correctly set and use a stream for writing data.
        - It creates a BytesIO buffer and writes data to the serializer
        - It verifies that the written data matches what was expected
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer()
        serializer.set_stream(buffer)
        serializer.write(b"hello")
        assert buffer.getvalue() == b"hello"

    def test_set_endianness(self):
        """
        This test verifies that the serializer can correctly set its endianness.
        - It creates a serializer with a BytesIO buffer and sets the endianness to little endian
        - It verifies that no exceptions are raised during the operation
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        serializer.set_endianness(Endianness.LITTLE_ENDIAN)

    def test_set_word_size(self):
        """
        This test verifies that the serializer can correctly set and retrieve its word size.
        - It creates a serializer with a BytesIO buffer
        - It checks the default word size is 8
        - It sets the word size to 4
        - It verifies that the word size was updated correctly
        """
        serializer = BinarySerializer(io.BytesIO())
        assert serializer.get_word_size() == 8
        serializer.set_word_size(4)
        assert serializer.get_word_size() == 4

    def test_seek(self):
        """
        This test verifies that the serializer can correctly seek to different positions in the
        stream.
        - It creates a serializer with a BytesIO buffer
        - It writes data and verifies the position advances correctly
        - It seeks back to the beginning and overwrites data
        - It verifies the final content matches expectations
        """
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
        """
        This test verifies that seeking fails appropriately when no stream is set.
        - It creates a serializer without setting a stream
        - It attempts to seek and expects a SerializationError to be raised
        """
        serializer = BinarySerializer()
        with pytest.raises(SerializationError):
            serializer.seek(5)

    def test_position_writer_not_set_error(self):
        """
        This test verifies that getting the position fails appropriately when no stream is set.
        - It creates a serializer without setting a stream
        - It attempts to get the position and expects a SerializationError to be raised
        """
        serializer = BinarySerializer()
        with pytest.raises(SerializationError):
            serializer.position()

    def test_write_error_writer_not_set(self):
        """
        This test verifies that writing fails appropriately when no stream is set.
        - It creates a serializer without setting a stream
        - It attempts to write data and expects a SerializationError to be raised
        """
        serializer = BinarySerializer()
        with pytest.raises(SerializationError):
            serializer.write(b"hello")

    def test_write_error_length(self):
        """
        This test verifies that writing fails when the buffer reports incorrect write length.
        - It creates a custom buffer that reports wrong write length
        - It attempts to write data with this faulty buffer
        - It expects a SerializationError to be raised due to length mismatch
        """

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
        """
        This test verifies that packing a string fails when the provided length is insufficient.
        - It creates a serializer with a BytesIO buffer
        - It attempts to pack a string with a length smaller than the string's actual length
        - It expects a SerializationError to be raised due to insufficient buffer space
        """
        buffer = io.BytesIO()
        serializer = BinarySerializer(buffer)
        string_value = "hello"
        with pytest.raises(SerializationError):
            serializer.pack_string(string_value, len(string_value) - 1)
