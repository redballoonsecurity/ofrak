import os
from dataclasses import dataclass
from typing import Dict, List, Union

import pytest

from ofrak import OFRAKContext
from ofrak.core.basic_block import BasicBlock
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.data import DataWord
from ofrak.core.elf.model import Elf
from ofrak.core.filesystem import File
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort
from ofrak_type.architecture import InstructionSetMode
from pytest_ofrak.patterns import TEST_PATTERN_ASSETS_DIR
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyTestCase,
    UnpackAndVerifyPattern,
)


@dataclass
class ComplexBlockUnpackerTestCase(UnpackAndVerifyTestCase[int, List[Union[BasicBlock, DataWord]]]):
    binary_filename: str
    binary_md5_digest: str


COMPLEX_BLOCK_UNPACKER_TEST_CASES = [
    ComplexBlockUnpackerTestCase(
        "x64",
        {
            0x4003E0: [
                BasicBlock(
                    virtual_address=0x4003E0,
                    size=42,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
            ],
            0x40040C: [
                BasicBlock(
                    virtual_address=0x40040C,
                    size=16,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195356,
                ),
                BasicBlock(
                    virtual_address=0x40041E,
                    size=5,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
                BasicBlock(
                    virtual_address=0x40041C,
                    size=2,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195358,
                ),
            ],
            0x400430: [
                BasicBlock(
                    virtual_address=0x400430,
                    size=18,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195394,
                ),
                BasicBlock(
                    virtual_address=0x40048D,
                    size=7,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
                BasicBlock(
                    virtual_address=0x400442,
                    size=32,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195426,
                ),
                BasicBlock(
                    virtual_address=0x400486,
                    size=7,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195469,
                ),
                BasicBlock(
                    virtual_address=0x400462,
                    size=6,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195432,
                ),
                BasicBlock(
                    virtual_address=0x400468,
                    size=30,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195462,
                ),
            ],
            0x4004A0: [
                BasicBlock(
                    virtual_address=0x4004A0,
                    size=14,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195502,
                ),
                BasicBlock(
                    virtual_address=0x4004C0,
                    size=2,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
                BasicBlock(
                    virtual_address=0x4004AE,
                    size=10,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195512,
                ),
                BasicBlock(
                    virtual_address=0x4004B8,
                    size=8,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
            ],
            0x4004C4: [
                BasicBlock(
                    virtual_address=0x4004C4,
                    size=25,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
            ],
            0x4004E0: [
                BasicBlock(
                    virtual_address=0x4004E0,
                    size=2,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
            ],
            0x4004F0: [
                BasicBlock(
                    virtual_address=0x4004F0,
                    size=74,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195642,
                ),
                BasicBlock(
                    virtual_address=0x400556,
                    size=35,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
                BasicBlock(
                    virtual_address=0x40053A,
                    size=6,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195648,
                ),
                BasicBlock(
                    virtual_address=0x400540,
                    size=22,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195670,
                ),
            ],
            0x400580: [
                BasicBlock(
                    virtual_address=0x400580,
                    size=22,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195734,
                ),
                BasicBlock(
                    virtual_address=0x4005AF,
                    size=7,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
                BasicBlock(
                    virtual_address=0x400596,
                    size=10,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195744,
                ),
                BasicBlock(
                    virtual_address=0x4005A0,
                    size=15,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=4195759,
                ),
            ],
        },
        set(),  # No optional results
        "hello.out",
        "cc2de3c0cd2d0ded7543682c2470fcf0",
    ),
    # ARM with literal pools
    ComplexBlockUnpackerTestCase(
        "ARM with literal pools",
        {
            0x8018: [
                BasicBlock(
                    virtual_address=0x8018,
                    size=24,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
                DataWord(virtual_address=0x8030, size=4, format_string="<L", xrefs_to=(32792,)),
            ],
            0x8034: [
                BasicBlock(
                    virtual_address=0x8034,
                    size=20,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=32840,
                ),
                BasicBlock(
                    virtual_address=0x8058,
                    size=8,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
                BasicBlock(
                    virtual_address=0x8048,
                    size=16,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=False,
                    exit_vaddr=32856,
                ),
                DataWord(virtual_address=0x8060, size=4, format_string="<L", xrefs_to=(32820,)),
                DataWord(virtual_address=0x8064, size=4, format_string="<L", xrefs_to=(32840,)),
            ],
            0x8068: [
                BasicBlock(
                    virtual_address=0x8068,
                    size=40,
                    mode=InstructionSetMode.NONE,
                    is_exit_point=True,
                    exit_vaddr=None,
                ),
            ],
        },
        set(),  # No optional results
        "simple_arm_gcc.o.elf",
        "c79d1bea0398d7a9d0faa1ba68786f5e",
    ),
    # ARM + Thumb, PIE
    ComplexBlockUnpackerTestCase(
        "PIE ARM with Thumb function",
        {
            0x140: [
                BasicBlock(0x140, 0x10, InstructionSetMode.THUMB, False, 0x150),
                BasicBlock(0x150, 0x6, InstructionSetMode.THUMB, False, 0x15A),
                BasicBlock(0x156, 0x4, InstructionSetMode.THUMB, False, 0x15A),
                BasicBlock(0x15A, 0xA, InstructionSetMode.THUMB, False, 0x192),
                BasicBlock(0x164, 0x6, InstructionSetMode.THUMB, False, 0x170),
                BasicBlock(0x16A, 0x6, InstructionSetMode.THUMB, False, 0x170),
                BasicBlock(0x170, 0x14, InstructionSetMode.THUMB, False, 0x184),
                BasicBlock(0x184, 0xE, InstructionSetMode.THUMB, False, 0x192),
                BasicBlock(0x192, 0x8, InstructionSetMode.THUMB, False, 0x19A),
                BasicBlock(0x19A, 0x12, InstructionSetMode.THUMB, True, None),
            ],
            0x110: [
                BasicBlock(0x110, 0x30, InstructionSetMode.NONE, True, None),
            ],
        },
        {
            0x1B0,  # __foo_from_arm
        },
        "simple_pie_thumb_bin",
        "fc7a6b95d993f955bd92f2bef2699dd0",
    ),
]


class ComplexBlockUnpackerUnpackAndVerifyPattern(UnpackAndVerifyPattern):
    """
    Test pattern which checks a ComplexBlockUnpacker implementation. This pattern is ready to go
    off-the-shelf. All that is needed to use it is
     1) A subclass with the name prefixed with "Test", and
     2) That subclass should be in a pytest context where the supplied frak context will have a
     ComplexBlockUnpacker implementation.

    This file includes test cases of the type ComplexBlockUnpackerTestCase. These include a URL
    which points to a binary which serves as the root resource. This binary will be unpacked
    recursively down to BasicBlocks, and all ComplexBlocks in the .text section will be
    extracted. Those ComplexBlocks should line up with the expected complex block virtual
    addresses; so should all of the BasicBlocks and DataWords that make up that ComplexBlock.
    Each of those are checked for some other specific expected attributes as well.
    """

    @pytest.fixture(params=COMPLEX_BLOCK_UNPACKER_TEST_CASES, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> ComplexBlockUnpackerTestCase:
        return request.param

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ComplexBlockUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(TEST_PATTERN_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        return resource

    async def unpack(self, root_resource: Resource):
        await root_resource.unpack_recursively(do_not_unpack=(BasicBlock,))

    async def get_descendants_to_verify(self, unpacked_resource: Resource) -> Dict[int, Resource]:
        elf = await unpacked_resource.view_as(Elf)
        text_section = await elf.get_section_by_name(".text")
        complex_blocks: List[ComplexBlock] = list(
            await text_section.resource.get_descendants_as_view(
                ComplexBlock,
                r_filter=ResourceFilter.with_tags(ComplexBlock),
                r_sort=ResourceSort(ComplexBlock.VirtualAddress),
            )
        )
        return {cb.virtual_address: cb for cb in complex_blocks}

    async def verify_descendant(
        self, complex_block: ComplexBlock, specified_result: List[Union[BasicBlock, DataWord]]
    ):
        basic_blocks = await complex_block.get_basic_blocks()

        # Check that the parent complex blocks are extracted as expected
        complex_block_start_address = complex_block.virtual_address
        # Check that all expected basic blocks have been extracted
        unpacked_bb_vaddrs = {basic_block.virtual_address for basic_block in basic_blocks}
        expected_bb_vaddrs = {
            expected_basic_block.virtual_address
            for expected_basic_block in specified_result
            if isinstance(expected_basic_block, BasicBlock)
        }

        assert (
            unpacked_bb_vaddrs == expected_bb_vaddrs
        ), f"Unpacked different BBs from CB 0x{complex_block_start_address:x}. All different basic blocks (expected XOR unpacked): {unpacked_bb_vaddrs.symmetric_difference(expected_bb_vaddrs)}"

        blocks_by_addr: Dict[int, Union[DataWord, BasicBlock]] = {
            block.virtual_address: block for block in specified_result
        }
        for basic_block in basic_blocks:
            expected_basic_block = blocks_by_addr[basic_block.virtual_address]
            assert type(expected_basic_block) is BasicBlock, (
                f"got BasicBlock at "
                f"{hex(basic_block.virtual_address)} but expected {type(expected_basic_block)}"
            )

            assert expected_basic_block == basic_block, (
                f"Extracted BasicBlocks do not match expected for ComplexBlock "
                f"0x{complex_block_start_address:x}: got {basic_block}, expected {expected_basic_block}"
            )

        data_words = await complex_block.get_data_words()
        unpacked_dw_vaddrs = {dw.virtual_address for dw in data_words}
        expected_dw_vaddrs = {
            expected_data_word.virtual_address
            for expected_data_word in specified_result
            if isinstance(expected_data_word, DataWord)
        }

        if unpacked_dw_vaddrs != expected_dw_vaddrs:
            expected_xor_unpacked = unpacked_dw_vaddrs.symmetric_difference(expected_dw_vaddrs)
            expected_xor_unpacked_str = ", ".join(hex(vaddr) for vaddr in expected_xor_unpacked)
            pytest.fail(
                f"Unpacked different DWs from CB 0x{complex_block_start_address:x}. All different data words (expected XOR unpacked): {expected_xor_unpacked_str}"
            )

        for data_word in data_words:
            expected_data_word = blocks_by_addr[data_word.virtual_address]
            assert type(expected_data_word) is DataWord, (
                f"got DataWord at "
                f"{hex(data_word.virtual_address)} but expected {type(expected_data_word)}"
            )
            assert expected_data_word == data_word, (
                f"Extracted DataWord do not match expected for ComplexBlock: "
                f"0x{complex_block_start_address:x}"
            )

    def _fixup_test_case_for_pie(
        self,
        expected_results: Dict[int, List[Union[BasicBlock, DataWord]]],
        pie_base_vaddr: int,
    ) -> Dict[int, List[Union[BasicBlock, DataWord]]]:
        """
        PIE files are loaded into some backends at an arbitrary offset
        For now OFRAK remaps its CodeRegions to match this, so test cases need to remap too

        :param pie_base_vaddr:
        :param expected_results:
        :return:
        """
        new_expected_results = {}
        for cb_vaddr, cb_children in expected_results.items():
            expected_children = []
            for child in cb_children:
                if isinstance(child, BasicBlock):
                    expected_children.append(
                        BasicBlock(
                            child.virtual_address + pie_base_vaddr,
                            child.size,
                            child.mode,
                            child.is_exit_point,
                            None if child.exit_vaddr is None else child.exit_vaddr + pie_base_vaddr,
                        )
                    )
                elif isinstance(child, DataWord):
                    expected_children.append(
                        DataWord(
                            child.virtual_address + pie_base_vaddr,
                            child.size,
                            child.format_string,
                            tuple(xref_vaddr + pie_base_vaddr for xref_vaddr in child.xrefs_to),
                        )
                    )

            new_expected_results[cb_vaddr + pie_base_vaddr] = expected_children

        return new_expected_results
