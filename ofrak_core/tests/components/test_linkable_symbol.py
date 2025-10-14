"""
This module tests the functionality of linkable symbols.
"""
import pytest

from ofrak.core import LinkableSymbol, LinkableSymbolType, LinkableSymbolStubInfo


@pytest.mark.parametrize(
    "linkable_symbol",
    [
        LinkableSymbol(0x1337, "leet_func", LinkableSymbolType.FUNC),
        LinkableSymbol(0x13337, "leet_ro_data", LinkableSymbolType.RO_DATA),
        LinkableSymbol(0x133337, "leet_rw_data", LinkableSymbolType.RW_DATA),
    ],
)
def test_linkable_symbol_stub_info(linkable_symbol: LinkableSymbol):
    """
    Test that it is possible to generate LinkableSymbolStubInfo for given linkable sybmol.

    This test verifies that:
    - A LinkableSymbolStubInfo can be generated for various symbol types
    """
    stub_info = linkable_symbol.get_stub_info()
    assert isinstance(stub_info, LinkableSymbolStubInfo)


def test_linkable_symbol_stub_info_undef():
    """
    Test that get_stub_info raises NotImplementedError for LinkableSymbolType.UNDEF.

    This test verifies that:
    - Attempting to generate stub info for an undefined symbol type raises NotImplementedError
    """
    linkable_symbol = LinkableSymbol(0x1337, "leet", LinkableSymbolType.UNDEF)
    with pytest.raises(NotImplementedError):
        _ = linkable_symbol.get_stub_info()
