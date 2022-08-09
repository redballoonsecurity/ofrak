import os.path
from dataclasses import dataclass
from typing import List, Dict

import pytest

from ofrak import OFRAKContext
from ofrak.core.basic_block import BasicBlock
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.filesystem import File
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort
from pytest_ofrak.patterns import TEST_PATTERN_ASSETS_DIR
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyPattern,
    UnpackAndVerifyTestCase,
)
from ofrak_type.range import Range


@dataclass
class CodeRegionUnpackerTestCase(UnpackAndVerifyTestCase[int, List[int]]):
    binary_filename: str
    binary_md5_digest: str


CODE_REGION_UNPACKER_TEST_CASES = [
    CodeRegionUnpackerTestCase(
        "x64",
        {
            ## Required cases
            0x40040C: [],  # .text:call_gmon_start
            0x400430: [],  # .text:__do_global_dtors_aux
            0x4004A0: [],  # .text:frame_dummy
            0x4004C4: [],  # .text:main
            0x4004E0: [],  # .text:__libc_csu_fini
            0x4004F0: [],  # .text:__libc_csu_init
            0x400580: [],  # .text:__do_global_ctors_aux
        },
        {
            ## Optional cases
            0x400390: [],  # .init:_init (loader import)
            0x4003A8: [],  # .plt:LAB_004003a8 (trampoline, ignored if in .plt)
            0x4003B8: [],  # .plt:puts (lib import thunk)
            0x4003C8: [],  # .plt:__libc_start_main (lib import thunk)
            0x4003E0: [],  # .text:_start (loader import)
            0x4005B8: [],  # .fini:_fini (loader import)
        },
        "hello.out",
        "cc2de3c0cd2d0ded7543682c2470fcf0",
    ),
    CodeRegionUnpackerTestCase(
        "x64 ELF nosections",
        {
            ## Required cases
            0x40040C: [],  # .text:call_gmon_start
            0x400430: [],  # .text:__do_global_dtors_aux
            0x4004A0: [],  # .text:frame_dummy
            0x4004C4: [],  # .text:main
            0x4004F0: [],  # .text:__libc_csu_init
            0x400580: [],  # .text:__do_global_ctors_aux
        },
        {
            ## Optional cases
            0x4003E0: [],  # .text:_start (loader import)
            0x400390: [],  # .init:_init (loader import)
            0x4003B8: [],  # .plt:puts (lib import thunk)
            0x4003C8: [],  # .plt:__libc_start_main (lib import thunk)
            0x4004E0: [],  # .text:__libc_csu_fini (handled ambiguously without .text hint)
            0x4005B8: [],  # .fini:_fini (loader import)
        },
        "hello_nosections.out",
        "56662f638390cae92c2cf5107bc3f1ef",
    ),
    CodeRegionUnpackerTestCase(
        "ARM ELF without literal pools",
        {
            0x8000: [],
            0x8030: [],
            0x8060: [],
            0x8094: [],
            0x8104: [],
        },
        {
            # No optional results
        },
        "arm_reloc_relocated.elf",
        "ed69056d3dbca810fa3a3f93db9e8927",
    ),
    CodeRegionUnpackerTestCase(
        "ARM ELF with literal pools",
        {
            0x8018: [0x8030],
            0x8034: [0x8060, 0x8064],
            0x8068: [],
        },
        {
            # .init
            0x8000: [],
            # .fini
            0x8090: [],
        },
        "simple_arm_gcc.o.elf",
        "c79d1bea0398d7a9d0faa1ba68786f5e",
    ),
]


class CodeRegionUnpackAndVerifyPattern(UnpackAndVerifyPattern):
    """
    Test pattern which checks a CodeRegionUnpacker implementation. This pattern is ready to go
    off-the-shelf. All that is needed to use it is
     1) A subclass with the name prefixed with "Test", and
     2) That subclass should be in a pytest context where the supplied frak context will have a
     CodeRegionUnpacker implementation.

    This file includes test cases of the type CodeRegionUnpackerTestCase. These include a URL
    which points to a binary which serves as the root resource. This binary will be unpacked
    recursively down to BasicBlocks, and all ComplexBlocks in the .text section will be
    extracted. Those ComplexBlocks should line up with the expected complex block virtual
    addresses, and if there are any data literals expected in the ComplexBlock those addresses are
    checked as well.
    """

    @pytest.fixture(params=CODE_REGION_UNPACKER_TEST_CASES, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> CodeRegionUnpackerTestCase:
        return request.param

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: CodeRegionUnpackerTestCase,
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
        program = await unpacked_resource.view_as(Program)
        code_regions = await program.get_code_regions()

        complex_blocks: List[ComplexBlock] = []

        for code_region in code_regions:
            complex_blocks += await code_region.resource.get_descendants_as_view(
                ComplexBlock,
                r_filter=ResourceFilter.with_tags(ComplexBlock),
                r_sort=ResourceSort(ComplexBlock.VirtualAddress),
            )

        return {cb.virtual_address: cb for cb in complex_blocks}

    async def verify_descendant(self, complex_block: ComplexBlock, specified_result: List[int]):
        start_address = complex_block.virtual_address
        end_address = start_address + complex_block.size
        # Check literal pools
        for lp_address in specified_result:
            assert lp_address in Range(
                start_address, end_address
            ), f"Literal pool at 0x{lp_address:x} not in extracted ComplexBlock {complex_block}"
