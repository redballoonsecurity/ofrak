import pytest

from ofrak_type.memory_permissions import MemoryPermissions


@pytest.mark.parametrize(
    "memory_permissions, expected_str",
    [
        (MemoryPermissions.R, "r"),
        (MemoryPermissions.W, "w"),
        (MemoryPermissions.X, "x"),
        (MemoryPermissions.RW, "rw"),
        (MemoryPermissions.RX, "rx"),
        (MemoryPermissions.WX, "wx"),
        (MemoryPermissions.RWX, "rwx"),
        (MemoryPermissions.NONE, "none"),
    ],
)
def test_memory_permissions_as_str(memory_permissions: MemoryPermissions, expected_str: str):
    assert memory_permissions.as_str() == expected_str


class TestMemoryPermissionsAdd:
    def test_add(self):
        # Basic additions
        assert MemoryPermissions.R + MemoryPermissions.X == MemoryPermissions.RX
        assert MemoryPermissions.R + MemoryPermissions.W == MemoryPermissions.RW
        assert MemoryPermissions.W + MemoryPermissions.X == MemoryPermissions.WX

        # Adding NONE should return the original
        assert MemoryPermissions.R + MemoryPermissions.NONE == MemoryPermissions.R
        assert MemoryPermissions.W + MemoryPermissions.NONE == MemoryPermissions.W
        assert MemoryPermissions.X + MemoryPermissions.NONE == MemoryPermissions.X
        assert MemoryPermissions.NONE + MemoryPermissions.NONE == MemoryPermissions.NONE

        # Building up to RWX
        assert MemoryPermissions.R + MemoryPermissions.WX == MemoryPermissions.RWX
        assert MemoryPermissions.W + MemoryPermissions.RX == MemoryPermissions.RWX
        assert MemoryPermissions.X + MemoryPermissions.RW == MemoryPermissions.RWX

    def test_add_type_error(self):
        with pytest.raises(TypeError):
            MemoryPermissions.R + 2  # type: ignore

    def test_add_value_error(self):
        with pytest.raises(ValueError):
            MemoryPermissions.R + MemoryPermissions.RWX  # type: ignore


class TestMemoryPermissionsAnd:
    def test_and(self):
        # Basic AND operations
        assert MemoryPermissions.RWX & MemoryPermissions.W == MemoryPermissions.W
        assert MemoryPermissions.RWX & MemoryPermissions.R == MemoryPermissions.R
        assert MemoryPermissions.RWX & MemoryPermissions.X == MemoryPermissions.X

        # AND with NONE always returns NONE
        assert MemoryPermissions.RWX & MemoryPermissions.NONE == MemoryPermissions.NONE
        assert MemoryPermissions.R & MemoryPermissions.NONE == MemoryPermissions.NONE
        assert MemoryPermissions.NONE & MemoryPermissions.NONE == MemoryPermissions.NONE

        # AND with itself returns itself
        assert MemoryPermissions.R & MemoryPermissions.R == MemoryPermissions.R
        assert MemoryPermissions.RW & MemoryPermissions.RW == MemoryPermissions.RW
        assert MemoryPermissions.RWX & MemoryPermissions.RWX == MemoryPermissions.RWX

        # Partial overlaps
        assert MemoryPermissions.RW & MemoryPermissions.RX == MemoryPermissions.R
        assert MemoryPermissions.RW & MemoryPermissions.WX == MemoryPermissions.W
        assert MemoryPermissions.RX & MemoryPermissions.WX == MemoryPermissions.X

        # No overlap returns NONE
        assert MemoryPermissions.R & MemoryPermissions.W == MemoryPermissions.NONE
        assert MemoryPermissions.R & MemoryPermissions.X == MemoryPermissions.NONE
        assert MemoryPermissions.W & MemoryPermissions.X == MemoryPermissions.NONE

    def test_and_type_error(self):
        with pytest.raises(TypeError):
            MemoryPermissions.R & 2  # type: ignore


class TestMemoryPermissionsSub:
    def test_sub(self):
        # Basic subtractions
        assert MemoryPermissions.RWX - MemoryPermissions.W == MemoryPermissions.RX
        assert MemoryPermissions.RWX - MemoryPermissions.R == MemoryPermissions.WX
        assert MemoryPermissions.RWX - MemoryPermissions.X == MemoryPermissions.RW

        # Subtracting NONE returns the original
        assert MemoryPermissions.RWX - MemoryPermissions.NONE == MemoryPermissions.RWX
        assert MemoryPermissions.R - MemoryPermissions.NONE == MemoryPermissions.R
        assert MemoryPermissions.NONE - MemoryPermissions.NONE == MemoryPermissions.NONE

        # Subtracting multiple permissions
        assert MemoryPermissions.RWX - MemoryPermissions.RW == MemoryPermissions.X
        assert MemoryPermissions.RWX - MemoryPermissions.RX == MemoryPermissions.W
        assert MemoryPermissions.RWX - MemoryPermissions.WX == MemoryPermissions.R

        # Subtracting all permissions
        assert MemoryPermissions.R - MemoryPermissions.R == MemoryPermissions.NONE
        assert MemoryPermissions.RW - MemoryPermissions.RW == MemoryPermissions.NONE
        assert MemoryPermissions.RWX - MemoryPermissions.RWX == MemoryPermissions.NONE

        # Partial subtraction
        assert MemoryPermissions.RW - MemoryPermissions.R == MemoryPermissions.W
        assert MemoryPermissions.RW - MemoryPermissions.W == MemoryPermissions.R

    def test_sub_type_error(self):
        with pytest.raises(TypeError):
            MemoryPermissions.R - 0  # type: ignore

    def test_sub_value_error(self):
        with pytest.raises(ValueError):
            MemoryPermissions.RW - MemoryPermissions.X  # type: ignore
            MemoryPermissions.NONE - MemoryPermissions.R  # type: ignore


class TestMemoryPermissionsEnumValues:
    """Test that the enum values are correct"""

    def test_enum_values(self):
        assert MemoryPermissions.NONE.value == 0
        assert MemoryPermissions.X.value == 1
        assert MemoryPermissions.W.value == 2
        assert MemoryPermissions.R.value == 4
        assert MemoryPermissions.RW.value == 6  # 4 + 2
        assert MemoryPermissions.RX.value == 5  # 4 + 1
        assert MemoryPermissions.WX.value == 3  # 2 + 1
        assert MemoryPermissions.RWX.value == 7  # 4 + 2 + 1


class TestMemoryPermissionsProperties:
    """Test mathematical properties of operations"""

    def test_inverse_operations(self):
        # Adding then subtracting should return original
        assert (
            MemoryPermissions.R + MemoryPermissions.W - MemoryPermissions.W == MemoryPermissions.R
        )
        assert (
            MemoryPermissions.W + MemoryPermissions.X - MemoryPermissions.X == MemoryPermissions.W
        )
        assert (
            MemoryPermissions.R + MemoryPermissions.X - MemoryPermissions.R == MemoryPermissions.X
        )

    def test_chained_operations(self):
        # Complex chained operations
        result = MemoryPermissions.NONE + MemoryPermissions.R
        result = result + MemoryPermissions.W
        result = result + MemoryPermissions.X
        assert result == MemoryPermissions.RWX

        # Subtract in reverse order
        result = result - MemoryPermissions.X
        result = result - MemoryPermissions.W
        result = result - MemoryPermissions.R
        assert result == MemoryPermissions.NONE
