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
            # Like Binary Ninja, angr does not include a trailing `hlt` instruction of basic blocks;
            # OFRAK expects it, so we increment the block expected size by 1 to include it
            basic_block: BasicBlock = unpack_verify_test_case.expected_results[0x4003E0][0]
            basic_block.size = 41

            # angr / vex considers function calls as BB terminators
            # https://github.com/redballoonsecurity/ofrak/issues/308
            self._split_bb(
                unpack_verify_test_case.expected_results, 5, 0x400430, 0x400468, 0x40047A
            )
            self._split_bb(
                unpack_verify_test_case.expected_results, 0, 0x4004C4, 0x4004C4, 0x4004D6
            )
            self._split_bb(
                unpack_verify_test_case.expected_results, 0, 0x4004F0, 0x4004F0, 0x400535
            )
            self._split_bb(
                unpack_verify_test_case.expected_results, 3, 0x4004F0, 0x400540, 0x40054D
            )
            self._split_bb(
                unpack_verify_test_case.expected_results, 3, 0x400580, 0x4005A0, 0x4005A6
            )

            return unpack_verify_test_case.expected_results

        elif unpack_verify_test_case.binary_md5_digest == "fc7a6b95d993f955bd92f2bef2699dd0":
            # angr / vex considers function calls as BB terminators
            # https://github.com/redballoonsecurity/ofrak/issues/308
            self._split_bb(
                unpack_verify_test_case.expected_results,
                0,
                0x110,
                0x110,
                0x130,
                keep_same_is_exit_point=False,
            )

            return self._fixup_test_case_for_pie(
                unpack_verify_test_case.expected_results,
                pie_base_vaddr=0x400000,
            )

        elif unpack_verify_test_case.binary_md5_digest == "c79d1bea0398d7a9d0faa1ba68786f5e":
            # Unlike angr 9.2.6, angr 9.2.77 and 9.2.91 miss this DataWord now
            # = the ref to it does not appear in the list of xrefs

            missing_data_words = {0x8030, 0x8060}

            fixed_up_results = {
                vaddr: [
                    block
                    for block in original_expected_blocks
                    if block.virtual_address not in missing_data_words
                ]
                for vaddr, original_expected_blocks in unpack_verify_test_case.expected_results.items()
            }

            return fixed_up_results

        return unpack_verify_test_case.expected_results

    def _split_bb(
        self,
        expected_results: Dict,
        idx,
        cb_addr,
        bb_1_addr,
        bb_2_addr,
        keep_same_is_exit_point: bool = False,
    ):
        """
        Split a BB at bb_2_addr, then populate self.unpack_verify_test_case.expected_results[cb_addr][idx]
        with the changes while appending the second half of the processed BB to expected_results.

        :param expected_results: Expected results to fix up in-place
        :param idx: Index offset of the test case within unpack_verify_test_case.expected_results[cb_addr]
        :param cb_addr: The complex block address which contains bb_1_addr
        :param bb_1_addr: entrypoint address of the BB to be split
        :param bb_2_addr: entrypoint address of the second half of the BB
        :param keep_same_is_exit_point: If True, both of the resulting BBs will have the same
         `is_exit_point` value as the parent, otherwise, only the second will "inherit" the
         parent's value (the first will have it set False)
        """
        bb_1: BasicBlock = expected_results[cb_addr][idx]

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
        if not keep_same_is_exit_point:
            bb_1.is_exit_point = False
            bb_1.exit_vaddr = bb_2_addr

        expected_results[cb_addr][idx] = bb_1
        expected_results[cb_addr].append(bb_2)
