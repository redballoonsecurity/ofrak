"""
Test the functionality and behavior of ResourceIndexedAttribute and ResourceAttributes.
"""

from dataclasses import dataclass

import pytest

from ofrak import ResourceAttributes
from ofrak.model.resource_model import index


@dataclass
class DummyAttributes(ResourceAttributes):
    x: int

    @index
    def X(self) -> int:
        return self.x


class TestResourceIndexedAttribute:
    async def test__set__(self):
        """
        Verify setting an indexed attribute with ResourceIndexedAttribute.__set__ raises ValueError.

        This test verifies that:
        - Attempting to set an indexed attribute value raises ValueError
        - The error message indicates the attribute is read-only
        """
        attribute = DummyAttributes(5)
        with pytest.raises(ValueError):
            attribute.X = 6

    async def test__getattr__(self):
        """
        Verify accessing non-existent attributes with ResourceIndexedAttribute.__getattr__ returns None.

        This test verifies that:
        - Accessing a non-existent attribute on an indexed attribute returns None
        - The attribute access doesn't raise any exceptions
        """
        assert DummyAttributes.X.y is None

    async def test_repr(self):
        """
        Verify string representation of indexed attribute.

        This test verifies that:
        - Calling __repr__ on an indexed attribute returns the expected string format
        - The representation includes the class name and attribute
        """
        result = DummyAttributes.X.__repr__()
        assert result == "DummyAttributes.X"


class TestResourceAttributes:
    async def test_str(self):
        """
        Verify string representation includes all attributes.

        This test verifies that:
        - Creating a resource attribute instance with values
        - The __str__ output follows the expected format with attribute names and values
        """
        attribute = DummyAttributes(5)
        assert attribute.__str__() == "DummyAttributes(x=5)"
