from typing import Dict

import pytest

from ofrak.core.basic_block import BasicBlock
from pytest_ofrak.patterns.code_region_unpacker import (
    CodeRegionUnpackAndVerifyPattern,
)
from pytest_ofrak.patterns.complex_block_unpacker import (
    ComplexBlockUnpackerTestCase,
    ComplexBlockUnpackerUnpackAndVerifyPattern,
)


class TestBinjaCodeRegionUnpackAndVerify(CodeRegionUnpackAndVerifyPattern):
    pass


class TestBinjaComplexBlockUnpackAndVerify(ComplexBlockUnpackerUnpackAndVerifyPattern):
    @pytest.fixture
    async def expected_results(self, unpack_verify_test_case: ComplexBlockUnpackerTestCase) -> Dict:
        if unpack_verify_test_case.binary_md5_digest == "cc2de3c0cd2d0ded7543682c2470fcf0":
            # Binary Ninja does not include a trailing `hlt` instruction as part of the basic block;
            #  since this is expected, we de decrement the block expected size to 41
            basic_block: BasicBlock = unpack_verify_test_case.expected_results[0x4003E0][0]
            basic_block.size = 41
        return unpack_verify_test_case.expected_results
