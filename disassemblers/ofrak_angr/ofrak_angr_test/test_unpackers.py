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


class TestAngrCodeRegionUnpackAndVerify(CodeRegionUnpackAndVerifyPattern):
    pass


class TestAngrComplexBlockUnpackAndVerify(ComplexBlockUnpackerUnpackAndVerifyPattern):
    @pytest.fixture
    async def expected_results(self, unpack_verify_test_case: ComplexBlockUnpackerTestCase) -> Dict:
        if unpack_verify_test_case.binary_md5_digest == "cc2de3c0cd2d0ded7543682c2470fcf0":
            self.unpack_verify_test_case = unpack_verify_test_case

            # Like Binary Ninja, angr does not include a trailing `hlt` instruction of basic blocks;
            # OFRAK expects it, so we increment the block expected size by 1 to include it
            basic_block: BasicBlock = unpack_verify_test_case.expected_results[0x4003E0][0]
            basic_block.size = 41

            # angr / vex considers indirect function calls as BB terminators
            self._split_bb(5, 0x400430, 0x400468, 0x40047A)
            self._split_bb(0, 0x4004C4, 0x4004C4, 0x4004D6)
            self._split_bb(0, 0x4004F0, 0x4004F0, 0x400535)
            self._split_bb(3, 0x4004F0, 0x400540, 0x40054D)
            self._split_bb(3, 0x400580, 0x4005A0, 0x4005A6)

        return unpack_verify_test_case.expected_results

    def _split_bb(self, idx, cb_addr, bb_1_addr, bb_2_addr):
        """
        Split a BB at bb_2_addr, then populate self.unpack_verify_test_case.expected_results[cb_addr][idx]
        with the changes while appending the second half of the processed BB to expected_results.

        :param idx: Index offset of the test case within unpack_verify_test_case.expected_results[cb_addr]
        :param cb_addr: The complex block address which contains bb_1_addr
        :param bb_1_addr: entrypoint address of the BB to be split
        :param bb_2_addr: entrypoint address of the second half of the BB
        """
        bb_1: BasicBlock = self.unpack_verify_test_case.expected_results[cb_addr][idx]

        bb_1_size = bb_2_addr - bb_1_addr
        bb_2_size = bb_1.size - bb_1_size

        bb_2 = BasicBlock(
            virtual_address=bb_2_addr,
            size=bb_2_size,
            mode=bb_1.mode,
            is_exit_point=bb_1.is_exit_point,
            exit_vaddr=bb_1.exit_vaddr,
        )

        bb_1.size = bb_1_size
        bb_1.is_exit_point = False
        bb_1.exit_vaddr = bb_2_addr

        self.unpack_verify_test_case.expected_results[cb_addr][idx] = bb_1
        self.unpack_verify_test_case.expected_results[cb_addr].append(bb_2)
