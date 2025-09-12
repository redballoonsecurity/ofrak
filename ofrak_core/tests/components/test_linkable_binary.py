import pytest
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

from ofrak import OFRAKContext
from ofrak.core import LinkableBinary, LinkableSymbol
from ofrak_type import LinkableSymbolType


class TestLinkableBinary:
    async def test_get_symbol(self, linkable_binary: LinkableBinary):
        """
        Assert that getting a unique symbol works.
        """
        symbol = await linkable_binary.get_only_symbol(name="main")
        assert isinstance(symbol, LinkableSymbol)

    async def test_duplicate_symbol(self, linkable_binary: LinkableBinary):
        """
        Assert that LinkableBinary.get_only_symbol raises an error when multiple symbols exist
        """
        with pytest.raises(NotFoundError):
            _ = await linkable_binary.get_only_symbol(name="key")

    async def test_nonexistent_symbol(self, linkable_binary: LinkableBinary):
        """
        Assert that LinkableBinary.get_only_symbol raises a NotFoundError when passed a non-existent
        symbol name.
        """
        with pytest.raises(NotFoundError):
            await linkable_binary.get_only_symbol(name="nonexistent_symbol")

    async def test_no_args(self, linkable_binary: LinkableBinary):
        """
        Assert that LinkableBinary.get_only_symbol raises a ValueError if neither name nor vaddr are
        specified.
        """
        with pytest.raises(ValueError):
            await linkable_binary.get_only_symbol()

    @pytest.fixture
    async def linkable_binary(self, ofrak_context: OFRAKContext) -> LinkableBinary:
        """
        Build a LinkableBinary for testing.
        """
        resource = await ofrak_context.create_root_resource("test_binary", b"\x00" * 100)
        resource.add_view(LinkableBinary())
        linkable_symbols = [
            LinkableSymbol(0x10, "main", LinkableSymbolType.FUNC),
            LinkableSymbol(0x20, "key", LinkableSymbolType.RW_DATA),
            LinkableSymbol(0x30, "key", LinkableSymbolType.RW_DATA),
        ]
        for symbol in linkable_symbols:
            _ = await resource.create_child_from_view(
                symbol, Range.from_size(symbol.virtual_address, 1)
            )
        await resource.save()
        return await resource.view_as(LinkableBinary)
