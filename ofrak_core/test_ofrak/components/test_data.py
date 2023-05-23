from dataclasses import dataclass

import pytest

from ofrak import OFRAKContext
from pytest_ofrak.patterns.data_refs_analyzer import (
    DataRefsAnalyzerTestPattern,
    DataRefsAnalyzerTestCase,
)

from ofrak.core import DataWord, ReferencedDataAttributes


@dataclass
class MockResource:
    data: bytes

    async def get_data(self):
        return self.data


@dataclass
class MockDataWord(DataWord):
    mock_resource: MockResource

    @property
    def resource(self):
        return self.mock_resource


@dataclass
class DataClassValueTestCase:
    data_word: MockDataWord
    expected_unsigned_value: int
    expected_signed_value: int


class TestDataWordGetValue:
    """
    Test that DataWord.{get_signed_value, get_unsigned_value} return correct values.
    """

    async def test_data_word_get_signed_value(self, data_word_test_case: DataClassValueTestCase):
        data_word = data_word_test_case.data_word
        expected_signed_value = data_word_test_case.expected_signed_value
        signed_value = await data_word.get_value_signed()
        assert signed_value == expected_signed_value

    async def test_data_word_get_unsigned_value(self, data_word_test_case: DataClassValueTestCase):
        data_word = data_word_test_case.data_word
        expected_unsigned_value = data_word_test_case.expected_unsigned_value
        unsigned_value = await data_word.get_value_unsigned()
        assert unsigned_value == expected_unsigned_value

    @pytest.fixture(
        params=[
            DataClassValueTestCase(
                MockDataWord(
                    0,
                    4,
                    ">I",
                    (),
                    MockResource(b"\x00\x00\x00\x00"),
                ),
                0,
                0,
            ),
            DataClassValueTestCase(
                MockDataWord(
                    0,
                    4,
                    ">I",
                    (),
                    MockResource(b"\xff\xff\xff\xff"),
                ),
                2**32 - 1,
                -1,
            ),
        ]
    )
    def data_word_test_case(self, request) -> DataClassValueTestCase:
        return request.param


class TestDataRefsAnalyzerLogic(DataRefsAnalyzerTestPattern):
    """
    Test that ReferencedDataAttributes.{get_xrefs_to, get_xrefs_from} logic is sound.
    """

    async def test_analyze_data_refs(
        self, ofrak_context: OFRAKContext, data_refs_test_case: DataRefsAnalyzerTestCase
    ):
        referencing_addresses = list()
        referenced_data = list()
        references = list()
        # Build up a ReferencedDataAttributes object without backend analysis.
        for i, reference in enumerate(data_refs_test_case.expected_references):
            from_vaddr, to_vaddr = reference
            referencing_addresses.append(from_vaddr)
            referenced_data.append(to_vaddr)
            references.append((i, i))
        data_refs = ReferencedDataAttributes(
            tuple(referencing_addresses), tuple(referenced_data), tuple(references)
        )
        await self.validate_data_refs(data_refs, data_refs_test_case)
