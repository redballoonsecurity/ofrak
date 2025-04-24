import pytest

from ofrak_type.memory_permissions import MemoryPermissions


@pytest.mark.parametrize(
    "memory_permissions, expected_str",
    [
        (MemoryPermissions.R, "r"),
        (MemoryPermissions.W, "w"),
        (MemoryPermissions.RWX, "rwx"),
        (MemoryPermissions.NONE, "none"),
    ],
)
def test_memory_permissions_as_str(memory_permissions: MemoryPermissions, expected_str: str):
    assert memory_permissions.as_str() == expected_str


class TestMemoryPermissionsAdd:
    def test_add(self):
        assert MemoryPermissions.R + MemoryPermissions.X == MemoryPermissions.RX
        assert MemoryPermissions.R + MemoryPermissions.NONE == MemoryPermissions.R

    def test_add_type_error(self):
        with pytest.raises(TypeError):
            MemoryPermissions.R + 2  # type: ignore

    def test_add_value_error(self):
        with pytest.raises(ValueError):
            MemoryPermissions.R + MemoryPermissions.RWX  # type: ignore


class TestMemoryPermissionsAnd:
    def test_and(self):
        assert MemoryPermissions.RWX & MemoryPermissions.W == MemoryPermissions.W
        assert MemoryPermissions.RWX & MemoryPermissions.NONE == MemoryPermissions.NONE

    def test_and_type_error(self):
        with pytest.raises(TypeError):
            MemoryPermissions.R & 2  # type: ignore


class TestMemoryPermissionsSub:
    def test_sub(self):
        assert MemoryPermissions.RWX - MemoryPermissions.W == MemoryPermissions.RX
        assert MemoryPermissions.RWX - MemoryPermissions.NONE == MemoryPermissions.RWX
        assert MemoryPermissions.NONE - MemoryPermissions.NONE == MemoryPermissions.NONE

    def test_sub_type_error(self):
        with pytest.raises(TypeError):
            MemoryPermissions.R - 0  # type: ignore

    def test_sub_value_error(self):
        with pytest.raises(ValueError):
            MemoryPermissions.RW - MemoryPermissions.X  # type: ignore
            MemoryPermissions.NONE - MemoryPermissions.R  # type: ignore
