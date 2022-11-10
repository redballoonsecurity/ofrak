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
        Assert that ResourceIndexedAttribute.__set__ raises a ValueError.
        """
        attribute = DummyAttributes(5)
        with pytest.raises(ValueError):
            attribute.X = 6

    async def test__getattr__(self):
        """
        Assert that ResourceIndexedAttribute.__getattr__ returns None if the attribute does not
        exist.
        """
        assert DummyAttributes.X.y is None

    async def test_repr(self):
        result = DummyAttributes.X.__repr__()
        assert result == "DummyAttributes.X"


class TestResourceAttributes:
    async def test_str(self):
        attribute = DummyAttributes(5)
        assert attribute.__str__() == "DummyAttributes(x=5)"
