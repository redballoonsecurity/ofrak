"""
This module tests the MemoryRegion component.

Requirements Mapping:
- REQ1.2
"""
from ofrak.core import MemoryRegion


def test_memory_region_str():
    """
    Test the string representation of a MemoryRegion.

    This test verifies that:
    - MemoryRegion objects can be properly converted to string representation
    """
    memory_region = MemoryRegion(0x100, 0x20)
    assert str(memory_region) == "MemoryRegion(0x100-0x120)"


def test_memory_region_hash():
    """
    Test the hashing behavior of a MemoryRegion.

    This test verifies that:
    - MemoryRegion objects can be used as hashable items in sets
    - MemoryRegion objects with same address and size are considered equal
    - MemoryRegion objects with different addresses or sizes are not equal
    """
    region_a = MemoryRegion(0x40, 0x10)
    region_b = MemoryRegion(0x40, 0x5)
    region_c = MemoryRegion(0x100, 0x5)
    memory_bank = {region_a, region_b}
    assert region_a in memory_bank
    assert region_b in memory_bank
    assert region_c not in memory_bank
