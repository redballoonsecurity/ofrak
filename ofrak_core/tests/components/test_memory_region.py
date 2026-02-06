"""
This module tests the MemoryRegion component.

Requirements Mapping:
- REQ1.2
"""
from ofrak.core import MemoryRegion
from ofrak.core.memory_region import MemoryRegionPermissions
from ofrak_type.memory_permissions import MemoryPermissions


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


class TestMemoryRegionPermissions:
    """Tests for MemoryRegionPermissions ResourceAttribute."""

    def test_memory_region_permissions_creation(self):
        """
        Test that MemoryRegionPermissions can be created with all permission types.
        """
        for perm in MemoryPermissions:
            perms_attr = MemoryRegionPermissions(permissions=perm)
            assert perms_attr.permissions == perm

    def test_memory_region_permissions_frozen(self):
        """
        Test that MemoryRegionPermissions is frozen (immutable).
        """
        import pytest

        perms_attr = MemoryRegionPermissions(permissions=MemoryPermissions.RX)
        with pytest.raises(AttributeError):
            perms_attr.permissions = MemoryPermissions.RW

    def test_memory_region_permissions_equality(self):
        """
        Test MemoryRegionPermissions equality comparison.
        """
        perms1 = MemoryRegionPermissions(permissions=MemoryPermissions.RX)
        perms2 = MemoryRegionPermissions(permissions=MemoryPermissions.RX)
        perms3 = MemoryRegionPermissions(permissions=MemoryPermissions.RW)

        assert perms1 == perms2
        assert perms1 != perms3
