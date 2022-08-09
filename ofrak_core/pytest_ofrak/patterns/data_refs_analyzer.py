import os
from dataclasses import dataclass
from typing import Tuple, List

import pytest

import test_ofrak.components

from ofrak import OFRAKContext
from ofrak.core.data import ReferencedDataAttributes


@dataclass
class DataRefsAnalyzerTestCase:
    """
    Test cases for ``DataRefsAnalyzerTestPattern``

    :ivar binary: path to binary to analyze
    :ivar expected_references: Expected analyzed references from func address to data address

    """

    binary: str
    expected_references: List[Tuple[int, int]]


DATA_REFS_TEST_CASES = [
    DataRefsAnalyzerTestCase(
        os.path.join(test_ofrak.components.ASSETS_DIR, "hello.out"),
        [(0x4004CC, 0x4005D8)],
    ),
    DataRefsAnalyzerTestCase(
        os.path.join(test_ofrak.components.ASSETS_DIR, "simple_arm_gcc.o.elf"),
        [(0x801C, 0x100B8)],
    ),
]


class DataRefsAnalyzerTestPattern:
    """
    Test pattern for testing DataRefsAnalyzer implementation for different frontends. Each test
    case should have at least all of the expected data refs analyzed successfully.

    """

    @pytest.fixture(params=DATA_REFS_TEST_CASES, ids=lambda tc: os.path.basename(tc.binary))
    async def data_refs_test_case(self, request) -> DataRefsAnalyzerTestCase:
        return request.param

    async def test_analyze_data_refs(
        self, ofrak_context: OFRAKContext, data_refs_test_case: DataRefsAnalyzerTestCase
    ):
        root_resource = await ofrak_context.create_root_resource_from_file(
            data_refs_test_case.binary
        )
        await root_resource.unpack()
        data_refs = await root_resource.analyze(ReferencedDataAttributes)
        assert 0 < len(data_refs.references)

        xrefs_to = data_refs.get_xrefs_to()
        xrefs_from = data_refs.get_xrefs_from()

        for expected_ref in data_refs_test_case.expected_references:
            from_vaddr, to_data = expected_ref

            assert from_vaddr in xrefs_to[to_data]
            assert to_data in xrefs_from[from_vaddr]
