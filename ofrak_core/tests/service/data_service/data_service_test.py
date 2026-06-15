"""
Test the internal implementation details of the DataService.
"""
import pytest

from ofrak.model.data_model import DataModel
from ofrak.service.error import OutOfBoundError
from ofrak_type.range import Range
from .conftest import DATA_1

from ofrak.service.data_service import DataService, _DataRoot, _PatchResizeTracker
from ofrak_type.error import NotFoundError


class TestDataService:
    async def test_get_root_by_id(self, populated_data_service: DataService):
        """
        Test that the DataService properly handles requests for non-existent data roots.
        - It checks that attempting to retrieve a root by an ID that doesn't exist raises a
        NotFoundError.
        """
        with pytest.raises(NotFoundError):
            populated_data_service._get_root_by_id(DATA_1)


class TestDataRoot:
    ROOT_ID = b"abracadabra"

    @pytest.fixture
    def data_root(self):
        model = DataModel(
            self.ROOT_ID,
            Range(0x0, 0x100),
            self.ROOT_ID,
        )

        return _DataRoot(
            model,
            b"\xed" * 0x100,
        )

    async def test_add_mapped_model(self, data_root: _DataRoot):
        """
        Test that the _DataRoot class correctly rejects models mapped outside its bounds.

        This test:
        - creates a model with a range that exceeds the root's boundaries.
        - checks that adding this out-of-bounds model raises an OutOfBoundError.
        """
        oob_model = DataModel(
            b"out of bounds",
            Range(0x120, 0x124),
            root_id=self.ROOT_ID,
        )
        with pytest.raises(OutOfBoundError):
            data_root.add_mapped_model(oob_model)

    async def test_delete_mapped_model(self, data_root: _DataRoot):
        """
        Test that the _DataRoot class correctly handles deletion of non-existent models.

        This test:
        - creates a model that is not present in the root's mapped models.
        - checks that attempting to delete this non-existent model raises a NotFoundError.
        """
        nonexistant_model = DataModel(
            b"does not exist",
            Range(0x80, 0x84),
            root_id=self.ROOT_ID,
        )
        with pytest.raises(NotFoundError):
            data_root.delete_mapped_model(nonexistant_model)


class TestPatchResizeTracker:
    """
    Test the functionality of shifting points based on patch resize operations.

    This test:
    - checks that points before a resized range are not shifted.
    - checks that points after a resized range are shifted correctly.
    - checks that points at the start of a resized range are not shifted.
    """

    @pytest.fixture
    def tracker(self):
        prt = _PatchResizeTracker()
        prt.add_new_resized_range(Range(0x10, 0x14), 0x8)
        return prt

    async def test_get_shifted_point(self, tracker: _PatchResizeTracker):
        """
        This test verifies that points after a resized range are shifted correctly.
        """
        assert tracker.get_shifted_point(0x0) == 0x0
        assert tracker.get_shifted_point(0x15) == 0x15 + 0x8
        assert tracker.get_shifted_point(0x10) == 0x10

    async def test_add_new_resized_range(self, tracker: _PatchResizeTracker):
        """
        Test the correct calculation of the total size difference after adding resized ranges.

        This test:
        - adds a new resized range with a negative size change.
        - checks that the total size difference is calculated correctly.
        """
        tracker.add_new_resized_range(Range(0x8, 0xA), -0x6)
        assert tracker.get_total_size_diff() == 0x2
