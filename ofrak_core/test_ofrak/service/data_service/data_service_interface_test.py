import pytest

from ofrak.model.data_model import DataPatch
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.error import (
    OutOfBoundError,
    PatchOverlapError,
)
from ofrak_type.error import AlreadyExistError, NotFoundError
from ofrak_type.range import Range
from test_ofrak.service.data_service.conftest import (
    DATA_0,
    DATA_1,
    DATA_2,
    DATA_3,
    DATA_4,
    DATA_5,
    DATA_6,
    DATA_7,
    DATA_8,
    DATA_TEST_0,
    DATA_TEST_1,
)


class TestDataServiceInterface:
    async def test_create_existing(self, populated_data_service: DataServiceInterface):
        with pytest.raises(AlreadyExistError):
            await populated_data_service.create_root(DATA_0, b"\x00" * 0x10)
        with pytest.raises(AlreadyExistError):
            await populated_data_service.create_mapped(DATA_1, DATA_0, Range(0x0, 0x8))

    async def test_create_missing_parent(self, populated_data_service: DataServiceInterface):
        with pytest.raises(NotFoundError):
            await populated_data_service.create_mapped(DATA_TEST_1, DATA_TEST_0, Range(0x0, 0x8))

    async def test_create_out_of_bounds(self, populated_data_service: DataServiceInterface):
        with pytest.raises(OutOfBoundError):
            await populated_data_service.create_mapped(DATA_TEST_0, DATA_0, Range(0x18, 0x20))

        with pytest.raises(OutOfBoundError):
            await populated_data_service.create_mapped(DATA_TEST_0, DATA_2, Range(0x4, 0x10))

    async def test_get_by_id(self, populated_data_service: DataServiceInterface):
        assert (await populated_data_service.get_by_id(DATA_0)).range == Range(0x0, 0x18)
        models = await populated_data_service.get_by_ids([DATA_1, DATA_2, DATA_3])
        assert [model.range for model in models] == [
            Range(0x0, 0x8),
            Range(0x8, 0x10),
            Range(0x8, 0xC),
        ]

        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_8 + DATA_8)

        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_ids([DATA_1, DATA_2, DATA_8 + DATA_8])

    async def test_get_data_length(self, populated_data_service: DataServiceInterface):
        assert 0x18 == await populated_data_service.get_data_length(DATA_0)
        assert 0x4 == await populated_data_service.get_data_length(DATA_4)

    async def test_get_range_within_other(self, populated_data_service: DataServiceInterface):
        assert Range(0x0, 0x8) == await populated_data_service.get_range_within_other(
            DATA_1, DATA_0
        )
        assert Range(0x8, 0xC) == await populated_data_service.get_range_within_other(
            DATA_3, DATA_0
        )
        assert Range(0x0, 0x4) == await populated_data_service.get_range_within_other(
            DATA_3, DATA_3
        )
        assert Range(0xC, 0xC) == await populated_data_service.get_range_within_other(
            DATA_3, DATA_4
        )

        with pytest.raises(ValueError):
            await populated_data_service.get_range_within_other(DATA_0, DATA_1)

        await populated_data_service.create_root(DATA_6, b"\x00" * 0x18)
        await populated_data_service.create_mapped(DATA_7, DATA_6, Range(0x2, 0x4))

        with pytest.raises(ValueError):
            await populated_data_service.get_range_within_other(DATA_7, DATA_0)

        with pytest.raises(ValueError):
            await populated_data_service.get_range_within_other(DATA_7, DATA_1)

    async def test_get_data(self, populated_data_service: DataServiceInterface):
        d = await populated_data_service.get_data(DATA_5)
        assert d == b"\x10" * 8

        d = await populated_data_service.get_data(DATA_0, Range(0xC, 0x14))
        assert d == b"\x00\x00\x00\x00\x10\x10\x10\x10"

        d = await populated_data_service.get_data(DATA_1, Range(0x18, 0x20))
        assert d == b""

        d = await populated_data_service.get_data(DATA_0, Range(0x18, 0x20))
        assert d == b""

    async def test_patches_out_of_bounds(self, populated_data_service: DataServiceInterface):
        with pytest.raises(OutOfBoundError):
            await populated_data_service.apply_patches(
                [DataPatch(Range(0x6, 0x9), DATA_1, b"\x01" * 0x3)]
            )

    async def test_patches_overlapping_resizes(self, populated_data_service: DataServiceInterface):
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x0, 0x2), DATA_2, b"\x01" * 5),
                    DataPatch(Range(0x1, 0x4), DATA_3, b"\x01" * 5),
                ]
            )
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x0, 0x2), DATA_3, b"\x01" * 5),
                    DataPatch(Range(0x1, 0x1), DATA_2, b"\x01" * 5),
                ]
            )
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x2, 0x2), DATA_3, b"\x01" * 5),
                    DataPatch(Range(0x2, 0x2), DATA_3, b"\x01" * 5),
                ]
            )
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    DataPatch(Range(0x2, 0x2), DATA_3, b"\x01" * 5),
                    DataPatch(Range(0x2, 0x2), DATA_2, b"\x01" * 5),
                ]
            )

    async def test_patches_overlapping_boundaries(
        self, populated_data_service: DataServiceInterface
    ):
        with pytest.raises(PatchOverlapError):
            results = await populated_data_service.apply_patches(
                [
                    # Resize region overlapping with DATA_3 end and DATA_4 start
                    DataPatch(Range(0x2, 0x6), DATA_2, b"\x01" * 5),
                ]
            )

    async def test_patches_overlapping_mapped_children(
        self, populated_data_service: DataServiceInterface
    ):
        results = await populated_data_service.apply_patches(
            [
                # Patch region overlapping with DATA_3 end and DATA_4 start, no resize
                DataPatch(Range(0x2, 0x6), DATA_2, b"\x01" * 4),
            ]
        )
        patched_data = await populated_data_service.get_data(DATA_2)
        assert patched_data == b"\x00\x00\x01\x01\x01\x01\x00\x00"
        results = await populated_data_service.apply_patches(
            [
                # Insert some on boundary between DATA_3 and DATA_4
                DataPatch(Range(0x4, 0x4), DATA_2, b"\x02" * 4),
            ]
        )
        patched_data = await populated_data_service.get_data(DATA_2)
        assert patched_data == b"\x00\x00\x01\x01\x02\x02\x02\x02\x01\x01\x00\x00"

    async def test_patches_trailing_children(self, populated_data_service: DataServiceInterface):
        results = await populated_data_service.apply_patches(
            [
                # Insert some data within DATA_0
                DataPatch(Range(0x00, 0x00), DATA_0, b"\x01" * 4),
            ]
        )

        data_1 = await populated_data_service.get_data(DATA_1)
        assert data_1 == b"\x00" * 0x8
        data_5 = await populated_data_service.get_data(DATA_5)
        assert data_5 == b"\x10" * 0x8
        data_3 = await populated_data_service.get_data(DATA_3)
        assert data_3 == b"\x00" * 0x4
        data_4 = await populated_data_service.get_data(DATA_4)
        assert data_4 == b"\x00" * 0x4
        data_2 = await populated_data_service.get_data(DATA_2)
        assert data_2 == b"".join(
            [
                b"\x00" * 4,  # Original data  (DATA_3)
                b"\x00" * 4,  # Original data  (DATA_4)
            ]
        )
        data_0 = await populated_data_service.get_data(DATA_0)
        assert data_0 == b"".join(
            [
                b"\x01" * 4,  # Patch           (DATA_0)
                b"\x00" * 0x10,  # Original data   (DATA_1)
                b"\x10" * 0x8,  # Original data    (DATA_5)
            ]
        )

    async def test_delete(self, populated_data_service: DataServiceInterface):
        """
        Starting state:
        DATA_0 (0x0, 0x18)  | [-----------------------)
        DATA_1 (0x0, 0x8)   | [-------)
        DATA_2 (0x8, 0x10)  |         [-------)
        DATA_3 (8x0, 0xC)   |         [---)
        DATA_4 (0xC, 0x10)  |             [---)
        DATA_5 (0x10, 0x18) |                 [-------)
        """

        await populated_data_service.delete_models((DATA_5,))
        """
        Expected state:
        DATA_0 (0x0, 0x18)  | [-----------------------)
        DATA_1 (0x0, 0x8)   | [-------)
        DATA_2 (0x8, 0x10)  |         [-------)
        DATA_3 (8x0, 0xC)   |         [---)
        DATA_4 (0xC, 0x10)  |             [---)
        """
        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_5)
        _ = await populated_data_service.get_by_ids([DATA_0, DATA_1, DATA_2, DATA_3, DATA_4])

        await populated_data_service.delete_models((DATA_2,))
        """
        Expected state:
        DATA_0 (0x0, 0x18)  | [-----------------------)
        DATA_1 (0x0, 0x8)   | [-------)
        DATA_3 (8x0, 0xC)   |         [---)
        DATA_4 (0xC, 0x10)  |             [---)
        """
        with pytest.raises(NotFoundError):
            await populated_data_service.get_by_id(DATA_2)
        (
            data_0_model,
            data_1_model,
            data_3_model,
            data_4_model,
        ) = await populated_data_service.get_by_ids([DATA_0, DATA_1, DATA_3, DATA_4])
        data_3_range = await populated_data_service.get_data_range_within_root(data_3_model.id)
        assert data_3_range == Range(0x8, 0xC)
        data_4_range = await populated_data_service.get_data_range_within_root(data_4_model.id)
        assert data_4_range == Range(0xC, 0x10)

        await populated_data_service.delete_models((DATA_1,))
        await populated_data_service.delete_models((DATA_3,))
        """
        Expected state:
        DATA_0 (0x0, 0x18)  | [-----------------------)
        DATA_4 (0xC, 0x10)  |             [---)
        """
        (
            data_0_model,
            data_4_model,
        ) = await populated_data_service.get_by_ids([DATA_0, DATA_4])
        data_4_range = await populated_data_service.get_data_range_within_root(data_4_model.id)
        assert data_4_range == Range(0xC, 0x10)

    async def test_delete_root(self, populated_data_service: DataServiceInterface):
        """
        Starting state:
        DATA_0 (0x0, 0x18)  | [-----------------------)
        DATA_1 (0x0, 0x8)   | [-------)
        DATA_2 (0x8, 0x10)  |         [-------)
        DATA_3 (8x0, 0xC)   |         [---)
        DATA_4 (0xC, 0x10)  |             [---)
        DATA_5 (0x10, 0x18) |                 [-------)
        """
        await populated_data_service.delete_models((DATA_0,))
        for data_id in [DATA_0, DATA_1, DATA_2, DATA_3, DATA_4, DATA_5]:
            with pytest.raises(NotFoundError):
                await populated_data_service.get_by_id(data_id)
