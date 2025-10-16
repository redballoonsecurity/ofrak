"""
Test BinaryDeserializer class and its error handling.
"""
import io

import pytest
from ofrak_io.deserializer import BinaryDeserializer, DeserializationError

from ofrak_type.endianness import Endianness


class TestBinaryDeserializer:
    """
    Test the BinaryDeserializer implementation.
    """

    def test_set_stream(self):
        """
        Test that deserializer can correctly set and read from a stream.

        This test verifies that:
        - Setting a stream allows reading data
        - Read position advances correctly
        - Data is read exactly as written
        """
        message = b"hello"
        deserializer = BinaryDeserializer()
        deserializer.set_stream(io.BytesIO(message))
        deserialized = deserializer.read(len(message))
        assert deserialized == message

    def test_set_endianness(self):
        """
        Test that the deserializer can configure its endianness setting.

        This test verifies that:
        - Endianness can be set
        - The configuration persists after setting
        """
        deserializer = BinaryDeserializer(io.BytesIO())
        deserializer.set_endianness(Endianness.LITTLE_ENDIAN)

    def test_set_word_size(self):
        """
        Test that the deserializer can configure its word size setting.

        This test verifies that:
        - Word size defaults to 8
        - Word size can be changed to 4
        - Changes to word size persist
        """
        deserializer = BinaryDeserializer(io.BytesIO())
        assert deserializer.get_word_size() == 8
        deserializer.set_word_size(4)
        assert deserializer.get_word_size() == 4

    def test_seek(self):
        """
        Test that the deserializer can seek to specific positions in the stream.

        This test verifies that:
        - Initial position starts at 0
        - Seek moves read position correctly
        - Reading after seek continues from new position
        - Seeking to start works properly
        """
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
        """
        Test that seeking without a configured stream raises an error.

        This test verifies that:
        - Attempting to seek with no stream raises DeserializationError
        """
        deserializer = BinaryDeserializer()
        with pytest.raises(DeserializationError):
            deserializer.seek(5)

    def test_position_error(self):
        """
        Test that position queries without a stream raise proper errors.

        This test verifies that:
        - Attempting to get position with no stream raises DeserializationError
        """
        deserializer = BinaryDeserializer()
        with pytest.raises(DeserializationError):
            deserializer.position()

    def test_read_error(self):
        """
        Test that read operations without a stream raise proper errors.

        This test verifies that:
        - Attempting to read with no stream raises DeserializationError
        """
        deserializer = BinaryDeserializer()
        with pytest.raises(DeserializationError):
            deserializer.read(5)

    def test_read_length_error(self):
        """
        Test that attempting to read beyond stream length raises an error.

        This test verifies that:
        - Reading from empty stream with positive length request raises DeserializationError
        """
        deserializer = BinaryDeserializer(io.BytesIO(b""))
        with pytest.raises(DeserializationError):
            deserializer.read(10)
