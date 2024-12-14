"""
Test ComplexBlock, BasicBlock, Instruction, DataWord primitives.
"""
import os
from dataclasses import dataclass
from typing import List, Union

import pytest
from ofrak_type.architecture import InstructionSetMode

from ofrak import OFRAKContext
from ofrak.core import (
    Elf,
    ComplexBlock,
    ProgramAttributes,
    BasicBlock,
    Instruction,
    DataWord,
    MemoryRegion,
)
from pytest_ofrak.patterns import TEST_PATTERN_ASSETS_DIR


class TestOfrakBlocks:
    """
    Test that exercises ComplexBlock, BasicBlock, Instruction, DataWord resource view methods.
    """

    def test_get_assembly(self, frame_dummy_complex_block: ComplexBlock):
        """
        Test that ComplexBlock.get_assembly returns an assembly string.
        """
        assembly = frame_dummy_complex_block.get_assembly()
        assert assembly == EXPECTED_ASSEMBLY

    def test_get_data_words(self, frame_dummy_complex_block: ComplexBlock):
        """
        Test that ComplexBlock.get_data_words returns the expected number of data words.
        """
        data_words = list(frame_dummy_complex_block.get_data_words())
        assert len(data_words) == 2

    @pytest.fixture
    def frame_dummy_complex_block(self, ofrak_context: OFRAKContext) -> ComplexBlock:
        """
        Unpack "arm_reloc_relocated.elf" and simulate unpacking the function "frame_dummy"
        recursively. This creates a tree of ComplexBlock, BasicBlock, Instruction, DataWords.
        """
        file_path = os.path.join(TEST_PATTERN_ASSETS_DIR, "arm_reloc_relocated.elf")

        resource = ofrak_context.create_root_resource_from_file(file_path)
        resource.unpack()
        elf = resource.view_as(Elf)
        program_attrs = elf.resource.analyze(ProgramAttributes)
        text_section = elf.get_section_by_name(".text")
        assert text_section is not None

        self._inflate_deflated_complex_block(DEFLATED_FRAME_DUMMY, text_section, (program_attrs,))
        return elf.get_function_complex_block("frame_dummy")

    @staticmethod
    def _inflate_deflated_complex_block(
        deflated_region: "DeflatedRegion", code_region: MemoryRegion, additional_attrs
    ):
        cb = code_region.create_child_region(deflated_region.region, additional_attrs)
        cb_view = cb.view_as(ComplexBlock)
        for child in deflated_region.children:
            inflated_child = cb_view.create_child_region(child.region, additional_attrs)
            for grandchild in child.children:
                assert isinstance(grandchild, MemoryRegion)
                mem_view = inflated_child.view_as(MemoryRegion)
                _ = mem_view.create_child_region(grandchild, additional_attrs)


@dataclass
class DeflatedRegion:
    region: MemoryRegion
    children: List[Union[MemoryRegion, "DeflatedRegion"]]


DEFLATED_FRAME_DUMMY = DeflatedRegion(
    ComplexBlock(0x8034, 0x34, "frame_dummy"),
    [
        DeflatedRegion(
            BasicBlock(0x8034, 0x14, InstructionSetMode.NONE, False, 0x8048),
            [
                Instruction(
                    0x8034,
                    0x4,
                    "ldr r0, [pc, #0x24]",
                    "ldr",
                    "r0, [pc, #0x24]",
                    InstructionSetMode.NONE,
                ),
                Instruction(
                    0x8038, 0x4, "push {r3, lr}", "push", "{r3, lr}", InstructionSetMode.NONE
                ),
                Instruction(
                    0x803C, 0x4, "ldr r3, [r0]", "ldr", "r3, [r0]", InstructionSetMode.NONE
                ),
                Instruction(
                    0x8040, 0x4, "cmp r3, #0x0", "cmp", "r3, #0x0", InstructionSetMode.NONE
                ),
                Instruction(0x8044, 0x4, "beq #0x8058", "beq", "#0x8058", InstructionSetMode.NONE),
            ],
        ),
        DeflatedRegion(
            BasicBlock(0x8048, 0x10, InstructionSetMode.NONE, False, 0x8058),
            [
                Instruction(
                    0x8048,
                    0x4,
                    "ldr r3, [pc, #0x14]",
                    "ldr",
                    "r3, [pc, #0x14]",
                    InstructionSetMode.NONE,
                ),
                Instruction(
                    0x804C, 0x4, "cmp r3, #0x0", "cmp", "r3, #0x0", InstructionSetMode.NONE
                ),
                Instruction(
                    0x8050, 0x4, "movne lr, pc", "movne", "lr, pc", InstructionSetMode.NONE
                ),
                Instruction(0x8054, 0x4, "bxne r3", "bxne", "re", InstructionSetMode.NONE),
            ],
        ),
        DeflatedRegion(
            BasicBlock(0x8058, 0x8, InstructionSetMode.NONE, True, None),
            [
                Instruction(0x8058, 0x4, "pop {r3, lr}", "pop", "{r3,lr}", InstructionSetMode.NONE),
                Instruction(0x805C, 0x4, "bx lr", "bx", "lr", InstructionSetMode.NONE),
            ],
        ),
        DeflatedRegion(DataWord(0x8060, 0x4, "<L", (0x8034,)), []),
        DeflatedRegion(DataWord(0x8064, 0x4, "<L", (0x8048,)), []),
    ],
)

EXPECTED_ASSEMBLY = """ldr r0, [pc, #0x24]
push {r3, lr}
ldr r3, [r0]
cmp r3, #0x0
beq #0x8058
ldr r3, [pc, #0x14]
cmp r3, #0x0
movne lr, pc
bxne re
pop {r3,lr}
bx lr"""
