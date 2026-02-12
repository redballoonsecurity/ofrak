"""
This module tests the MemoryRegion component.

Requirements Mapping:
- REQ1.2
"""
import pytest

from ofrak import OFRAKContext
from ofrak.core import CodeRegion, MemoryRegion
from ofrak.core.memory_region import (
    MemoryRegionPermissions,
    get_memory_region_permissions,
    get_effective_memory_permissions,
)
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


async def test_get_effective_memory_permissions_explicit(ofrak_context: OFRAKContext):
    """Explicit MemoryRegionPermissions override the CodeRegion/default heuristic."""
    resource = await ofrak_context.create_root_resource("test", b"\x00" * 8)
    resource.add_tag(CodeRegion)
    resource.add_attributes(MemoryRegionPermissions(MemoryPermissions.W))
    # Would be RX from the CodeRegion tag, but explicit attribute wins
    assert get_effective_memory_permissions(resource) == MemoryPermissions.W


async def test_get_effective_memory_permissions_code_region_fallback(ofrak_context: OFRAKContext):
    """Without explicit permissions, CodeRegion resources default to RX."""
    resource = await ofrak_context.create_root_resource("test", b"\x00" * 8)
    resource.add_tag(CodeRegion)
    assert get_effective_memory_permissions(resource) == MemoryPermissions.RX


async def test_get_memory_region_permissions_absent(ofrak_context: OFRAKContext):
    """get_memory_region_permissions returns None when no attribute is set."""
    resource = await ofrak_context.create_root_resource("test", b"\x00" * 8)
    assert get_memory_region_permissions(resource) is None
