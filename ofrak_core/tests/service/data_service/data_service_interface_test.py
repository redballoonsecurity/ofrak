"""
Test the DataServiceInterface, which is responsible for managing data models and
their relationships within the OFRAK framework.
"""

import re

import pytest

from ofrak.model.data_model import DataPatch
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.error import (
    OutOfBoundError,
    PatchOverlapError,
)
from ofrak_type.error import AlreadyExistError, NotFoundError
from ofrak_type.range import Range
from .conftest import (
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
        """
        Test the creation of data models in the data service, ensuring that creating existing or
        invalid models raises appropriate errors.

        This test verifies that:
        - Creating a root data model with an existing ID raises AlreadyExistError
        - Creating a mapped data model with an existing ID raises AlreadyExistError
        - Creating a mapped data model without a parent raises NotFoundError
        """
        with pytest.raises(AlreadyExistError):
            await populated_data_service.create_root(DATA_0, b"\x00" * 0x10)
        with pytest.raises(AlreadyExistError):
            await populated_data_service.create_mapped(DATA_1, DATA_0, Range(0x0, 0x8))

    async def test_create_missing_parent(self, populated_data_service: DataServiceInterface):
        """
        Test creating a mapped data model without a parent, which should raise NotFoundError.
        """
        with pytest.raises(NotFoundError):
            await populated_data_service.create_mapped(DATA_TEST_1, DATA_TEST_0, Range(0x0, 0x8))

    async def test_create_out_of_bounds(self, populated_data_service: DataServiceInterface):
        """
        Test creating a mapped data model with an out-of-bounds range, which should raise OutOfBoundError.
        """
        with pytest.raises(OutOfBoundError):
            await populated_data_service.create_mapped(DATA_TEST_0, DATA_0, Range(0x18, 0x20))

        with pytest.raises(OutOfBoundError):
            await populated_data_service.create_mapped(DATA_TEST_0, DATA_2, Range(0x4, 0x10))

    async def test_get_by_id(self, populated_data_service: DataServiceInterface):
        """
        Test retrieving data models by ID or IDs from the data service.

        This test verifies that:
        - Retrieving a single existing model by ID returns the correct model
        - Retrieving multiple existing models by IDs returns the correct models in order
        - Retrieving a non-existent model by ID raises NotFoundError
        - Retrieving a list containing a non-existent model raises NotFoundError
        """
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
        """
        Test retrieving the length of data models from the data service.

        This test verifies that:
        - Retrieving the length of an existing model returns the correct length
        """
        assert 0x18 == await populated_data_service.get_data_length(DATA_0)
        assert 0x4 == await populated_data_service.get_data_length(DATA_4)

    async def test_get_range_within_other(self, populated_data_service: DataServiceInterface):
        """
        Test retrieving the range of one data model within another data model.

        This test verifies that:
        - Retrieving a valid range within another model returns the correct range
        - Retrieving a range that is invalid (e.g., not contained) raises ValueError
        """
        assert Range(0x0, 0x8) == await populated_data_service.get_range_within_other(
            DATA_1, DATA_0
        )
        assert Range(0x8, 0xC) == await populated_data_service.get_range_within_other(
            DATA_3, DATA_0
        )
        assert Range(0x0, 0x4) == await populated_data_service.get_range_within_other(
            DATA_3, DATA_3
        )
        assert Range(0x0, 0x0) == await populated_data_service.get_range_within_other(
            DATA_3, DATA_4
        )

        assert Range(0x4, 0x8) == await populated_data_service.get_range_within_other(
            DATA_4, DATA_2
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
        """
        Test retrieving data content from data models.

        This test verifies that:
        - Retrieving data from a model returns the correct bytes
        - Retrieving data with a specific range within a model returns the correct bytes
        - Retrieving data outside of a model's bounds returns empty bytes
        """
        d = await populated_data_service.get_data(DATA_5)
        assert d == b"\x10" * 8

        d = await populated_data_service.get_data(DATA_0, Range(0xC, 0x14))
        assert d == b"\x00\x00\x00\x00\x10\x10\x10\x10"

        d = await populated_data_service.get_data(DATA_1, Range(0x18, 0x20))
        assert d == b""

        d = await populated_data_service.get_data(DATA_0, Range(0x18, 0x20))
        assert d == b""

    async def test_patches_out_of_bounds(self, populated_data_service: DataServiceInterface):
        """
        Test applying patches that are out-of-bounds, which should raise OutOfBoundError.

        This test verifies that:
        - Applying a patch with an out-of-bounds range raises OutOfBoundError
        """
        with pytest.raises(OutOfBoundError):
            await populated_data_service.apply_patches(
                [DataPatch(Range(0x6, 0x9), DATA_1, b"\x01" * 0x3)]
            )

    async def test_patches_overlapping_resizes(self, populated_data_service: DataServiceInterface):
        """
        Test applying patches that cause overlapping resizes, which should raise PatchOverlapError.

        This test verifies that:
        - Applying patches that overlap in a way that causes resizing conflicts raises PatchOverlapError
        """
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
        """
        Test applying patches that overlap at boundaries, which should raise PatchOverlapError.

        This test verifies that:
        - Applying a patch that overlaps the boundary between two regions raises PatchOverlapError
        """
        with pytest.raises(PatchOverlapError):
            await populated_data_service.apply_patches(
                [
                    # Resize region overlapping with DATA_3 end and DATA_4 start
                    DataPatch(Range(0x2, 0x6), DATA_2, b"\x01" * 5),
                ]
            )

    async def test_patches_overlapping_mapped_children(
        self, populated_data_service: DataServiceInterface
    ):
        """
        Test applying patches that overlap with mapped children, which should handle resizing correctly.

        This test verifies that:
        - Applying a patch that resizes a mapped child correctly updates the parent and child models
        - Applying a patch that overlaps boundaries between children correctly updates all affected models
        - Applying an insert patch at a boundary correctly updates all affected models
        """
        results = await populated_data_service.apply_patches(
            [
                # Resize entirety of a mapped child
                DataPatch(Range(0x0, 0x8), DATA_1, b"\xaa" * 0xA)
            ]
        )
        """
        DATA_0 (0x0, 0x1A)  | [-----------------------)
        DATA_1 (0x0, 0xA)   | [---------)
        DATA_2 (0xA, 0x12)  |           [-------)
        DATA_3 (0xA, 0xE)   |           [---)
        DATA_4 (0xE, 0x12)  |               [---)
        DATA_5 (0x12, 0x1A) |                   [-------)
        """
        patched_data = await populated_data_service.get_data(DATA_1)
        assert patched_data == b"\xaa" * 0xA
        modified_ranges = {res.data_id: res.patches for res in results}
        assert modified_ranges == {DATA_0: [Range(0x0, 0x8)], DATA_1: [Range(0x0, 0x8)]}

        results = await populated_data_service.apply_patches(
            [
                # Patch region overlapping with DATA_3 end and DATA_4 start, no resize
                DataPatch(Range(0x2, 0x6), DATA_2, b"\x01" * 4),
            ]
        )
        """
        DATA_0 (0x0, 0x1A)  | [-----------------------)
        DATA_1 (0x0, 0xA)   | [---------)
        DATA_2 (0xA, 0x12)  |           [-------)
        DATA_3 (0xA, 0xE)   |           [---)
        DATA_4 (0xE, 0x12)  |               [---)
        DATA_5 (0x12, 0x1A) |                   [-------)
        """
        patched_data = await populated_data_service.get_data(DATA_2)
        assert patched_data == b"\x00\x00\x01\x01\x01\x01\x00\x00"
        modified_ranges = {res.data_id: res.patches for res in results}
        assert modified_ranges == {
            DATA_0: [Range(0xC, 0x10)],
            DATA_2: [Range(0x2, 0x6)],
            DATA_3: [Range(0x2, 0x4)],
            DATA_4: [Range(0x0, 0x2)],
        }

        results = await populated_data_service.apply_patches(
            [
                # Insert some data on boundary between DATA_3 and DATA_4
                DataPatch(Range(0x4, 0x4), DATA_2, b"\x02" * 4),
            ]
        )
        """
        DATA_0 (0x0, 0x1E)  | [---------------------------)
        DATA_1 (0x0, 0xA)   | [---------)
        DATA_2 (0xA, 0x16)  |           [-----------)
        DATA_3 (0xA, 0xE)   |           [---)
        DATA_4 (0x12, 0x16) |                   [---)
        DATA_5 (0x16, 0x1E) |                       [-------)
        """
        patched_data = await populated_data_service.get_data(DATA_2)
        assert patched_data == b"\x00\x00\x01\x01\x02\x02\x02\x02\x01\x01\x00\x00"
        modified_ranges = {res.data_id: res.patches for res in results}
        assert modified_ranges == {DATA_0: [Range(0xE, 0xE)], DATA_2: [Range(0x4, 0x4)]}

        data_3 = await populated_data_service.get_data(DATA_3)
        assert data_3 == b"\x00\x00\x01\x01"

    async def test_patches_trailing_children(self, populated_data_service: DataServiceInterface):
        """
        Test applying patches that affect trailing children.

        This test verifies that:
        - Applying a patch at the beginning of a data model correctly adjusts the ranges of subsequent models
        """
        results = await populated_data_service.apply_patches(
            [
                # Insert some data within DATA_0
                DataPatch(Range(0x00, 0x00), DATA_0, b"\x01" * 4),
            ]
        )
        modified_ranges = {res.data_id: res.patches for res in results}
        assert modified_ranges == {DATA_0: [Range(0x0, 0x0)]}

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

    async def test_patch_resizes_to_zero(self, populated_data_service: DataServiceInterface):
        """
        Test applying patches that resize a model to zero length.

        This test verifies that:
        - Applying a patch that resizes a model to zero length correctly updates the parent model's
        range and removes the child model
        """
        await populated_data_service.apply_patches(
            [
                # Resize DATA_4 to 0
                DataPatch(Range(0x0, 0x4), DATA_4, b""),
            ]
        )
        """
        DATA_0 (0x0, 0x14)  | [-------------------)
        DATA_1 (0x0, 0x8)   | [-------)
        DATA_2 (0x8, 0xC)   |         [---)
        DATA_3 (0x8, 0xC)   |         [---)
        DATA_4 (0xC, 0xC)   |             )
        DATA_5 (0xC, 0x14)  |             [-------)
        """
        model_0, model_2, model_3, model_4, model_5 = await populated_data_service.get_by_ids(
            (DATA_0, DATA_2, DATA_3, DATA_4, DATA_5)
        )
        assert model_0.range == Range(0x0, 0x14)
        assert model_2.range == Range(0x8, 0xC)
        assert model_3.range == Range(0x8, 0xC)
        assert model_4.range == Range(0xC, 0xC)
        assert model_5.range == Range(0xC, 0x14)

        await populated_data_service.apply_patches(
            [
                # Resize DATA_3 to 0
                DataPatch(Range(0x0, 0x4), DATA_3, b""),
            ]
        )
        """
        DATA_0 (0x0, 0x14)  | [-------------------)
        DATA_1 (0x0, 0x8)   | [-------)
        DATA_2 (0x8, 0xC)   |         [---)
        DATA_3 (0x8, 0x8)   |         )
        DATA_4 (0x8, 0x8)   |         )
        DATA_5 (0x8, 0x10)  |         [-------)
        """

        model_0, model_2, model_3, model_4, model_5 = await populated_data_service.get_by_ids(
            (DATA_0, DATA_2, DATA_3, DATA_4, DATA_5)
        )
        assert model_0.range == Range(0x0, 0x10)
        assert model_2.range == Range(0x8, 0x8)
        assert model_3.range == Range(0x8, 0x8)
        assert model_4.range == Range(0x8, 0x8)
        assert model_5.range == Range(0x8, 0x10)

        assert b"" == await populated_data_service.get_data(DATA_2)

    async def test_delete(self, populated_data_service: DataServiceInterface):
        """
        Test deleting data models from the data service.

        This test verifies that:
        - Deleting a single model removes it and adjusts the parent's range correctly
        - Deleting a root model removes all its children recursively

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
        await populated_data_service.get_by_ids([DATA_0, DATA_1, DATA_2, DATA_3, DATA_4])

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
        Test deleting a root data model, which should remove all its children recursively.

        This test verifies that:
        - Deleting a root model removes the root and all its descendants

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

    async def test_search_bytes(self, populated_data_service: DataServiceInterface):
        """
        Test searching for byte patterns within data models.

        This test verifies that:
        - Searching for a specific byte pattern returns the correct position(s)
        - Searching with start and end parameters limits the search range correctly
        """
        (results,) = await populated_data_service.search(DATA_0, b"\x00\x10")
        assert results == 0x10 - 1

        results = await populated_data_service.search(DATA_0, b"\x10", start=0x10)
        assert results == (0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17)

    async def test_search_regex(self, populated_data_service: DataServiceInterface):
        """
        Test searching for regular expressions within data models.

        This test verifies that:
        - Searching for a regex pattern returns the correct match(es) with positions and matched bytes
        - Searching with start and end parameters limits the search range correctly
        """
        results = await populated_data_service.search(DATA_0, re.compile(b"\x00\x10+"))
        assert results == ((0x10 - 1, b"\x00\x10\x10\x10\x10\x10\x10\x10\x10"),)

        results = await populated_data_service.search(
            DATA_0, re.compile(b"\x00+\x10+"), start=0xC, end=0x14
        )
        assert results == ((0xC, b"\x00\x00\x00\x00\x10\x10\x10\x10"),)
