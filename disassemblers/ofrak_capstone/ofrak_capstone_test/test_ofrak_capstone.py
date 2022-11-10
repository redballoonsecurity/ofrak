import os
from binascii import unhexlify
from dataclasses import dataclass
from typing import Dict, List

import pytest

from ofrak.core import BinaryPatchModifier, BinaryPatchConfig
from ofrak.core.filesystem import File

import ofrak_capstone
from ofrak import OFRAKContext
from ofrak.model.viewable_tag_model import ResourceViewContext
from ofrak_type.architecture import InstructionSet, InstructionSetMode
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.basic_block import BasicBlock
from ofrak.core.instruction import Instruction
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort
from pytest_ofrak.patterns import TEST_PATTERN_ASSETS_DIR
from pytest_ofrak.patterns.basic_block_unpacker import (
    BasicBlockUnpackerUnpackAndVerifyPattern,
    BasicBlockUnpackerTestCase,
)
from pytest_ofrak.patterns.register_usage_analyzer import (
    RegisterAnalyzerTestCase,
    RegisterUsageTestPattern,
)
from test_ofrak.constants import ARM32_ARCH

pytest_plugins = ["pytest_ofrak.fixtures"]


@pytest.fixture
def test_id():
    return "TEST_JOB"


@pytest.fixture(autouse=True)
def capstone_components(ofrak_injector):
    ofrak_injector.discover(ofrak_capstone)


class TestCapstoneBasicBlockUnpackAndVerify(BasicBlockUnpackerUnpackAndVerifyPattern):
    async def unpack(self, root_resource: Resource):
        basic_block_resources = await root_resource.get_descendants(
            r_filter=ResourceFilter.with_tags(BasicBlock),
        )
        for bb_r in basic_block_resources:
            await bb_r.unpack()

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: BasicBlockUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        """
        Some hacky logic in here to avoid needing to unpack the whole resource top to bottom
        (which would require an analysis backend) and instead define the basic blocks manually.
        The hacky part is that the root resource is duplicated with all its data, once as the
        root resource (which gets unpacked so that we can analyze the ProgramAttributes for the
        capstone BB unpacker's benefit) and a second time as an unmapped child of that root
        resource, which does not get unpacked but instead has basic block children manually
        mapped into it.
        """
        asset_path = os.path.join(TEST_PATTERN_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        top_resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        await top_resource.unpack()
        resource = await top_resource.create_child(
            data=binary_data,
        )

        for bb_vaddr, bb_range in unpack_verify_test_case.basic_block_data_ranges_in_root.items():
            await resource.create_child_from_view(
                BasicBlock(bb_vaddr, bb_range.length(), InstructionSetMode.NONE, False, None),
                data_range=bb_range,
            )
        return resource

    async def get_descendants_to_verify(self, unpacked_resource: Resource) -> Dict[int, Resource]:
        basic_blocks = await unpacked_resource.get_descendants_as_view(
            BasicBlock,
            r_filter=ResourceFilter.with_tags(BasicBlock),
            r_sort=ResourceSort(BasicBlock.VirtualAddress),
        )
        return {bb.virtual_address: bb for bb in basic_blocks}


@dataclass
class UnpackerTestCase:
    label: str
    program_attributes: ProgramAttributes
    parent_basic_block: BasicBlock
    basic_block_data: bytes
    expected_children: List[Instruction]

    async def run_instruction_unpacker_test_case(self, ofrak: OFRAKContext):
        bb_r = await self._initialize_basic_bloc_resource(ofrak)

        await bb_r.unpack()

        children = list(
            await bb_r.get_children_as_view(
                Instruction, r_sort=ResourceSort(BasicBlock.VirtualAddress)
            )
        )

        assert len(self.expected_children) == len(children), (
            f"Did not unpack the expected number"
            f" of children (expected {len(self.expected_children)})"
        )

        for expected_child, child in zip(self.expected_children, children):
            assert expected_child == child

    async def run_instruction_analzyer_test_case(self, ofrak: OFRAKContext):
        bb_r = await self._initialize_basic_bloc_resource(ofrak)
        await bb_r.unpack()
        basic_block = await bb_r.view_as(BasicBlock)
        for instruction in await basic_block.get_instructions():
            raw_bytes = await instruction.resource.get_data()
            # Patch ourselves
            await instruction.resource.run(BinaryPatchModifier, BinaryPatchConfig(0, raw_bytes))
            # Clear context to get resource view again, triggering InstructionAnalyzer. Without
            # this step the InstructionAnalyzer does not run.
            instruction.resource._resource_view_context = ResourceViewContext()
            reanalyzed_instruction = await instruction.resource.view_as(Instruction)
            assert instruction == reanalyzed_instruction

    async def _initialize_basic_bloc_resource(self, ofrak) -> Resource:
        bb_r = await ofrak.create_root_resource(
            "test_resource", self.basic_block_data, tags=(Program,)
        )
        bb_r.add_view(self.parent_basic_block)
        bb_r.add_attributes(self.program_attributes)
        await bb_r.save()
        return bb_r


BASIC_BLOCK_TEST_CASES = [
    UnpackerTestCase(
        "Arm32",
        ARM32_ARCH,
        BasicBlock(
            0x100,
            0x14,
            InstructionSetMode.NONE,
            False,
            None,
        ),
        unhexlify("F0412DE90040A0E30450A0E150609FE550709FE5"),
        [
            Instruction(
                0x100,
                0x4,
                "push {r4, r5, r6, r7, r8, lr}",
                "push",
                "{r4, r5, r6, r7, r8, lr}",
                InstructionSetMode.NONE,
            ),
            Instruction(
                0x104,
                0x4,
                "mov r4, #0x0",
                "mov",
                "r4, #0x0",
                InstructionSetMode.NONE,
            ),
            Instruction(
                0x108,
                0x4,
                "mov r5, r4",
                "mov",
                "r5, r4",
                InstructionSetMode.NONE,
            ),
            Instruction(
                0x10C,
                0x4,
                "ldr r6, [pc, #0x50]",
                "ldr",
                "r6, [pc, #0x50]",
                InstructionSetMode.NONE,
            ),
            Instruction(
                0x110,
                0x4,
                "ldr r7, [pc, #0x50]",
                "ldr",
                "r7, [pc, #0x50]",
                InstructionSetMode.NONE,
            ),
        ],
    )
]


@pytest.mark.parametrize("test_case", BASIC_BLOCK_TEST_CASES, ids=lambda tc: tc.label)
async def test_capstone_unpacker(test_case, ofrak_context):
    await test_case.run_instruction_analzyer_test_case(ofrak_context)


@pytest.mark.parametrize("test_case", BASIC_BLOCK_TEST_CASES, ids=lambda tc: tc.label)
async def test_capstone_analyzer(test_case, ofrak_context):
    await test_case.run_instruction_analzyer_test_case(ofrak_context)


class TestCapstoneRegisterUsage(RegisterUsageTestPattern):
    def case_is_known_broken(self, test_case: RegisterAnalyzerTestCase):
        if test_case.program_attributes.isa is InstructionSet.PPC:
            return True, "capstone fails to give register usage info for PPC instructions"

        elif test_case.program_attributes.isa is InstructionSet.X86:
            mnemonics = {"call"}
            if (
                test_case.instruction.mnemonic not in mnemonics
                and "rip" not in test_case.instruction.operands
                and "rip" in test_case.expected_regs_read
            ):
                return (
                    True,
                    "capstone fails to find some implicit rip reads",
                )
        return False, ""
