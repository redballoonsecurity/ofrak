"""
Tests for specific internals of the DataService implementation of the DataServiceInterface, which
would be convoluted to test using only the public interface.

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
        oob_model = DataModel(
            b"out of bounds",
            Range(0x120, 0x124),
            root_id=self.ROOT_ID,
        )
        with pytest.raises(OutOfBoundError):
            data_root.add_mapped_model(oob_model)

    async def test_delete_mapped_model(self, data_root: _DataRoot):
        nonexistant_model = DataModel(
            b"does not exist",
            Range(0x80, 0x84),
            root_id=self.ROOT_ID,
        )
        with pytest.raises(NotFoundError):
            data_root.delete_mapped_model(nonexistant_model)


class TestPatchResizeTracker:
    @pytest.fixture
    def tracker(self):
        prt = _PatchResizeTracker()
        prt.add_new_resized_range(Range(0x10, 0x14), 0x8)
        return prt

    async def test_get_shifted_point(self, tracker: _PatchResizeTracker):
        assert tracker.get_shifted_point(0x0) == 0x0
        assert tracker.get_shifted_point(0x15) == 0x15 + 0x8
        assert tracker.get_shifted_point(0x10) == 0x10

    async def test_add_new_resized_range(self, tracker: _PatchResizeTracker):
        tracker.add_new_resized_range(Range(0x8, 0xA), -0x6)
        assert tracker.get_total_size_diff() == 0x2
