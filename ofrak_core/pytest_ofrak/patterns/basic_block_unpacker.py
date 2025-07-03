import os
from dataclasses import dataclass
from typing import Dict, List, Union, Tuple

import pytest
from ofrak.core.filesystem import File

from ofrak.resource import Resource

from ofrak import OFRAKContext
from ofrak_type.architecture import InstructionSetMode
from ofrak.core.basic_block import BasicBlock
from ofrak.core.instruction import Instruction
from ofrak.service.resource_service_i import ResourceFilter, ResourceSort
from ofrak.core.elf.model import Elf
from pytest_ofrak.patterns import TEST_PATTERN_ASSETS_DIR
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyTestCase,
    UnpackAndVerifyPattern,
)
from ofrak_type.range import Range

ExpectedBasicBlockUnpackResult = Union[Instruction, Tuple[Instruction, ...]]


@dataclass
class BasicBlockUnpackerTestCase(
    UnpackAndVerifyTestCase[int, List[ExpectedBasicBlockUnpackResult]]
):
    binary_filename: str
    binary_md5_digest: str
    basic_block_data_ranges_in_root: Dict[int, Range]  # Used when created basic blocks manually


BASIC_BLOCK_UNPACKER_TEST_CASES = [
    BasicBlockUnpackerTestCase(
        "x64",
        {
            0x4003E0: [
                Instruction(
                    virtual_address=0x4003E0,
                    size=2,
                    mnemonic="xor",
                    operands="ebp, ebp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4003E2,
                    size=3,
                    mnemonic="mov",
                    operands="r9, rdx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4003E5,
                    size=1,
                    mnemonic="pop",
                    operands="rsi",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4003E6,
                    size=3,
                    mnemonic="mov",
                    operands="rdx, rsp",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x4003E9,
                        size=4,
                        mnemonic="and",
                        operands="rsp, -0x10",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4003E9,
                        size=4,
                        mnemonic="and",
                        operands="rsp, 0xfffffffffffffff0",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x4003ED,
                    size=1,
                    mnemonic="push",
                    operands="rax",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4003EE,
                    size=1,
                    mnemonic="push",
                    operands="rsp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4003EF,
                    size=7,
                    mnemonic="mov",
                    operands="r8, 0x4004e0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4003F6,
                    size=7,
                    mnemonic="mov",
                    operands="rcx, 0x4004f0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4003FD,
                    size=7,
                    mnemonic="mov",
                    operands="rdi, 0x4004c4",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400404,
                    size=5,
                    mnemonic="call",
                    operands="0x4003c8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400409,
                    size=1,
                    mnemonic="hlt",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x40040C: [
                Instruction(
                    virtual_address=0x40040C,
                    size=4,
                    mnemonic="sub",
                    operands="rsp, 0x8",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400410,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [0x600840]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400410,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [rip + 0x200429]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x400417,
                    size=3,
                    mnemonic="test",
                    operands="rax, rax",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x40041A,
                        size=2,
                        mnemonic="jz",
                        operands="0x40041e",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x40041A,
                        size=2,
                        mnemonic="je",
                        operands="0x40041e",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x40041E: [
                Instruction(
                    virtual_address=0x40041E,
                    size=4,
                    mnemonic="add",
                    operands="rsp, 0x8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400422,
                    size=1,
                    mnemonic="ret",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x40041C: [
                Instruction(
                    virtual_address=0x40041C,
                    size=2,
                    mnemonic="call",
                    operands="rax",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x400430: [
                Instruction(
                    virtual_address=0x400430,
                    size=1,
                    mnemonic="push",
                    operands="rbp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400431,
                    size=3,
                    mnemonic="mov",
                    operands="rbp, rsp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400434,
                    size=1,
                    mnemonic="push",
                    operands="rbx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400435,
                    size=4,
                    mnemonic="sub",
                    operands="rsp, 0x8",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400439,
                        size=7,
                        mnemonic="cmp",
                        operands="byte ptr [0x600880], 0x0",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400439,
                        size=7,
                        mnemonic="cmp",
                        operands="byte ptr [rip + 0x200440], 0x0",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                (
                    Instruction(
                        virtual_address=0x400440,
                        size=2,
                        mnemonic="jnz",
                        operands="0x40048d",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400440,
                        size=2,
                        mnemonic="jne",
                        operands="0x40048d",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x40048D: [
                Instruction(
                    virtual_address=0x40048D,
                    size=4,
                    mnemonic="add",
                    operands="rsp, 0x8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400491,
                    size=1,
                    mnemonic="pop",
                    operands="rbx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400492,
                    size=1,
                    mnemonic="leave",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400493,
                    size=1,
                    mnemonic="ret",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x400442: [
                Instruction(
                    virtual_address=0x400442,
                    size=5,
                    mnemonic="mov",
                    operands="ebx, 0x6006a0",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400447,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [0x600888]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400447,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [rip + 0x20043a]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x40044E,
                    size=7,
                    mnemonic="sub",
                    operands="rbx, 0x600698",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400455,
                    size=4,
                    mnemonic="sar",
                    operands="rbx, 0x3",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400459,
                    size=4,
                    mnemonic="sub",
                    operands="rbx, 0x1",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40045D,
                    size=3,
                    mnemonic="cmp",
                    operands="rax, rbx",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400460,
                        size=2,
                        mnemonic="jnc",
                        operands="0x400486",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400460,
                        size=2,
                        mnemonic="jae",
                        operands="0x400486",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x400486: [
                (
                    Instruction(
                        virtual_address=0x400486,
                        size=7,
                        mnemonic="mov",
                        operands="byte ptr [0x600880], 0x1",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400486,
                        size=7,
                        mnemonic="mov",
                        operands="byte ptr [rip + 0x2003f3], 0x1",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x400462: [
                (
                    Instruction(
                        virtual_address=0x400462,
                        size=6,
                        mnemonic="nop",
                        operands="word ptr [rax + rax*0x1]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400462,
                        size=6,
                        mnemonic="nop",
                        operands="word ptr [rax + rax]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x400468: [
                Instruction(
                    virtual_address=0x400468,
                    size=4,
                    mnemonic="add",
                    operands="rax, 0x1",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x40046C,
                        size=7,
                        mnemonic="mov",
                        operands="qword ptr [0x600888], rax",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x40046C,
                        size=7,
                        mnemonic="mov",
                        operands="qword ptr [rip + 0x200415], rax",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                (
                    Instruction(
                        virtual_address=0x400473,
                        size=7,
                        mnemonic="call",
                        operands="qword ptr [0x600698 + rax*0x8]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400473,
                        size=7,
                        mnemonic="call",
                        operands="qword ptr [rax*0x8 + 0x600698]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                (
                    Instruction(
                        virtual_address=0x40047A,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [0x600888]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x40047A,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [rip + 0x200407]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x400481,
                    size=3,
                    mnemonic="cmp",
                    operands="rax, rbx",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400484,
                        size=2,
                        mnemonic="jc",
                        operands="0x400468",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400484,
                        size=2,
                        mnemonic="jb",
                        operands="0x400468",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x4004A0: [
                (
                    Instruction(
                        virtual_address=0x4004A0,
                        size=8,
                        mnemonic="cmp",
                        operands="qword ptr [0x6006a8], 0x0",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4004A0,
                        size=8,
                        mnemonic="cmp",
                        operands="qword ptr [rip + 0x200200], 0x0",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x4004A8,
                    size=1,
                    mnemonic="push",
                    operands="rbp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004A9,
                    size=3,
                    mnemonic="mov",
                    operands="rbp, rsp",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x4004AC,
                        size=2,
                        mnemonic="jz",
                        operands="0x4004c0",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4004AC,
                        size=2,
                        mnemonic="je",
                        operands="0x4004c0",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x4004C0: [
                Instruction(
                    virtual_address=0x4004C0,
                    size=1,
                    mnemonic="leave",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004C1,
                    size=1,
                    mnemonic="ret",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x4004AE: [
                Instruction(
                    virtual_address=0x4004AE,
                    size=5,
                    mnemonic="mov",
                    operands="eax, 0x0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004B3,
                    size=3,
                    mnemonic="test",
                    operands="rax, rax",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x4004B6,
                        size=2,
                        mnemonic="jz",
                        operands="0x4004c0",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4004B6,
                        size=2,
                        mnemonic="je",
                        operands="0x4004c0",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x4004B8: [
                Instruction(
                    virtual_address=0x4004B8,
                    size=5,
                    mnemonic="mov",
                    operands="edi, 0x6006a8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004BD,
                    size=1,
                    mnemonic="leave",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004BE,
                    size=2,
                    mnemonic="jmp",
                    operands="rax",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x4004C4: [
                Instruction(
                    virtual_address=0x4004C4,
                    size=1,
                    mnemonic="push",
                    operands="rbp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004C5,
                    size=3,
                    mnemonic="mov",
                    operands="rbp, rsp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004C8,
                    size=4,
                    mnemonic="sub",
                    operands="rsp, 0x10",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004CC,
                    size=5,
                    mnemonic="mov",
                    operands="edi, 0x4005d8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004D1,
                    size=5,
                    mnemonic="call",
                    operands="0x4003b8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004D6,
                    size=5,
                    mnemonic="mov",
                    operands="eax, 0x0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004DB,
                    size=1,
                    mnemonic="leave",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004DC,
                    size=1,
                    mnemonic="ret",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x4004E0: [
                (
                    Instruction(
                        virtual_address=0x4004E0,
                        size=2,
                        mnemonic="ret",
                        operands="",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4004E0,
                        size=2,
                        mnemonic="rep ret",
                        operands="",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4004E0,
                        size=2,
                        mnemonic="repz ret",
                        operands="",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x4004F0: [
                Instruction(
                    virtual_address=0x4004F0,
                    size=5,
                    mnemonic="mov",
                    operands="qword ptr [rsp - 0x28], rbp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4004F5,
                    size=5,
                    mnemonic="mov",
                    operands="qword ptr [rsp - 0x20], r12",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x4004FA,
                        size=7,
                        mnemonic="lea",
                        operands="rbp, [0x600684]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4004FA,
                        size=7,
                        mnemonic="lea",
                        operands="rbp, [rip + 0x200183]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                (
                    Instruction(
                        virtual_address=0x400501,
                        size=7,
                        mnemonic="lea",
                        operands="r12, [0x600684]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400501,
                        size=7,
                        mnemonic="lea",
                        operands="r12, [rip + 0x20017c]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x400508,
                    size=5,
                    mnemonic="mov",
                    operands="qword ptr [rsp - 0x18], r13",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40050D,
                    size=5,
                    mnemonic="mov",
                    operands="qword ptr [rsp - 0x10], r14",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400512,
                    size=5,
                    mnemonic="mov",
                    operands="qword ptr [rsp - 0x8], r15",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400517,
                    size=5,
                    mnemonic="mov",
                    operands="qword ptr [rsp - 0x30], rbx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40051C,
                    size=4,
                    mnemonic="sub",
                    operands="rsp, 0x38",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400520,
                    size=3,
                    mnemonic="sub",
                    operands="rbp, r12",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400523,
                    size=3,
                    mnemonic="mov",
                    operands="r13d, edi",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400526,
                    size=3,
                    mnemonic="mov",
                    operands="r14, rsi",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400529,
                    size=4,
                    mnemonic="sar",
                    operands="rbp, 0x3",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40052D,
                    size=3,
                    mnemonic="mov",
                    operands="r15, rdx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400530,
                    size=5,
                    mnemonic="call",
                    operands="0x400390",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400535,
                    size=3,
                    mnemonic="test",
                    operands="rbp, rbp",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400538,
                        size=2,
                        mnemonic="jz",
                        operands="0x400556",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400538,
                        size=2,
                        mnemonic="je",
                        operands="0x400556",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x400556: [
                Instruction(
                    virtual_address=0x400556,
                    size=5,
                    mnemonic="mov",
                    operands="rbx, qword ptr [rsp + 0x8]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40055B,
                    size=5,
                    mnemonic="mov",
                    operands="rbp, qword ptr [rsp + 0x10]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400560,
                    size=5,
                    mnemonic="mov",
                    operands="r12, qword ptr [rsp + 0x18]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400565,
                    size=5,
                    mnemonic="mov",
                    operands="r13, qword ptr [rsp + 0x20]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40056A,
                    size=5,
                    mnemonic="mov",
                    operands="r14, qword ptr [rsp + 0x28]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40056F,
                    size=5,
                    mnemonic="mov",
                    operands="r15, qword ptr [rsp + 0x30]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400574,
                    size=4,
                    mnemonic="add",
                    operands="rsp, 0x38",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400578,
                    size=1,
                    mnemonic="ret",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x40053A: [
                Instruction(
                    virtual_address=0x40053A,
                    size=2,
                    mnemonic="xor",
                    operands="ebx, ebx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x40053C,
                    size=4,
                    mnemonic="nop",
                    operands="dword ptr [rax]",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x400540: [
                Instruction(
                    virtual_address=0x400540,
                    size=3,
                    mnemonic="mov",
                    operands="rdx, r15",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400543,
                    size=3,
                    mnemonic="mov",
                    operands="rsi, r14",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400546,
                    size=3,
                    mnemonic="mov",
                    operands="edi, r13d",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400549,
                    size=4,
                    mnemonic="call",
                    operands="qword ptr [r12 + rbx*0x8]",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x40054D,
                        size=4,
                        mnemonic="add",
                        operands="rbx, 0x1",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x40054D,
                        size=4,
                        mnemonic="add",
                        operands="rbx, 1",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x400551,
                    size=3,
                    mnemonic="cmp",
                    operands="rbx, rbp",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400554,
                        size=2,
                        mnemonic="jc",
                        operands="0x400540",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400554,
                        size=2,
                        mnemonic="jb",
                        operands="0x400540",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x400580: [
                Instruction(
                    virtual_address=0x400580,
                    size=1,
                    mnemonic="push",
                    operands="rbp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400581,
                    size=3,
                    mnemonic="mov",
                    operands="rbp, rsp",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400584,
                    size=1,
                    mnemonic="push",
                    operands="rbx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x400585,
                    size=4,
                    mnemonic="sub",
                    operands="rsp, 0x8",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400589,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [0x600688]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400589,
                        size=7,
                        mnemonic="mov",
                        operands="rax, qword ptr [rip + 0x2000f8]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x400590,
                    size=4,
                    mnemonic="cmp",
                    operands="rax, -0x1",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x400594,
                        size=2,
                        mnemonic="jz",
                        operands="0x4005af",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x400594,
                        size=2,
                        mnemonic="je",
                        operands="0x4005af",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x4005AF: [
                Instruction(
                    virtual_address=0x4005AF,
                    size=4,
                    mnemonic="add",
                    operands="rsp, 0x8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4005B3,
                    size=1,
                    mnemonic="pop",
                    operands="rbx",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4005B4,
                    size=1,
                    mnemonic="leave",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4005B5,
                    size=1,
                    mnemonic="ret",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x400596: [
                Instruction(
                    virtual_address=0x400596,
                    size=5,
                    mnemonic="mov",
                    operands="ebx, 0x600688",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x40059B,
                        size=5,
                        mnemonic="nop",
                        operands="dword ptr [rax + rax*0x1]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x40059B,
                        size=5,
                        mnemonic="nop",
                        operands="dword ptr [rax + rax]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x4005A0: [
                Instruction(
                    virtual_address=0x4005A0,
                    size=4,
                    mnemonic="sub",
                    operands="rbx, 0x8",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4005A4,
                    size=2,
                    mnemonic="call",
                    operands="rax",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4005A6,
                    size=3,
                    mnemonic="mov",
                    operands="rax, qword ptr [rbx]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x4005A9,
                    size=4,
                    mnemonic="cmp",
                    operands="rax, -0x1",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x4005AD,
                        size=2,
                        mnemonic="jnz",
                        operands="0x4005a0",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x4005AD,
                        size=2,
                        mnemonic="jne",
                        operands="0x4005a0",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
        },
        set(),  # No optional results
        "hello.out",
        "cc2de3c0cd2d0ded7543682c2470fcf0",
        {
            0x4003E0: Range(0x3E0, 0x40A),
            0x40040C: Range(0x40C, 0x41C),
            0x40041E: Range(0x41E, 0x423),
            0x40041C: Range(0x41C, 0x41E),
            0x400430: Range(0x430, 0x442),
            0x40048D: Range(0x48D, 0x494),
            0x400442: Range(0x442, 0x462),
            0x400486: Range(0x486, 0x48D),
            0x400462: Range(0x462, 0x468),
            0x400468: Range(0x468, 0x486),
            0x4004A0: Range(0x4A0, 0x4AE),
            0x4004C0: Range(0x4C0, 0x4C2),
            0x4004AE: Range(0x4AE, 0x4B8),
            0x4004B8: Range(0x4B8, 0x4C0),
            0x4004C4: Range(0x4C4, 0x4DD),
            0x4004E0: Range(0x4E0, 0x4E2),
            0x4004F0: Range(0x4F0, 0x53A),
            0x400556: Range(0x556, 0x579),
            0x40053A: Range(0x53A, 0x540),
            0x400540: Range(0x540, 0x556),
            0x400580: Range(0x580, 0x596),
            0x4005AF: Range(0x5AF, 0x5B6),
            0x400596: Range(0x596, 0x5A0),
            0x4005A0: Range(0x5A0, 0x5AF),
        },
    ),
    # x64 Kernel address space - ensure large 64-bit addresses are interpreted as unsigned
    BasicBlockUnpackerTestCase(
        "x64 Kernel address space",
        {
            0xFFFFFFFF80000000: [
                Instruction(
                    virtual_address=0xFFFFFFFF80000000,
                    size=5,
                    mnemonic="mov",
                    operands="eax, 0x0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0xFFFFFFFF80000005,
                    size=1,
                    mnemonic="ret",
                    operands="",
                    mode=InstructionSetMode.NONE,
                ),
            ],
        },
        set(),  # No optional results
        "kernel_address_space.out",
        "242dd5b9ecc56bb7a8c8db43e8c720f0",
        {
            0xFFFFFFFF80000000: Range(0x1000, 0x1006),
        },
    ),
    # ARM with literal pools
    BasicBlockUnpackerTestCase(
        "ARM with literal pools",
        {
            0x8018: [
                (
                    Instruction(
                        virtual_address=0x8018,
                        size=4,
                        mnemonic="ldr",
                        operands="r3, [pc, #0x10]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8018,
                        size=4,
                        mnemonic="ldr",
                        operands="r3, [0x8030]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                (
                    Instruction(
                        virtual_address=0x801C,
                        size=4,
                        mnemonic="ldrb",
                        operands="r2, [r3, #0x0]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x801C,
                        size=4,
                        mnemonic="ldrb",
                        operands="r2, [r3]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x8020,
                    size=4,
                    mnemonic="cmp",
                    operands="r2, #0x0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8024,
                    size=4,
                    mnemonic="moveq",
                    operands="r2, #0x1",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x8028,
                        size=4,
                        mnemonic="strbeq",
                        operands="r2, [r3, #0x0]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8028,
                        size=4,
                        mnemonic="strbeq",
                        operands="r2, [r3]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x802C,
                    size=4,
                    mnemonic="bx",
                    operands="lr",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x8034: [
                (
                    Instruction(
                        virtual_address=0x8034,
                        size=4,
                        mnemonic="ldr",
                        operands="r0, [0x8060]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8034,
                        size=4,
                        mnemonic="ldr",
                        operands="r0, [pc, #0x24]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                (
                    Instruction(
                        virtual_address=0x8038,
                        size=4,
                        mnemonic="stmdb",
                        operands="sp!, {r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8038,
                        size=4,
                        mnemonic="stmdb",
                        operands="sp!, {r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8038,
                        size=4,
                        mnemonic="stmdb",
                        operands="sp!, {r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8038,
                        size=4,
                        mnemonic="push",
                        operands="{r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                (
                    Instruction(
                        virtual_address=0x803C,
                        size=4,
                        mnemonic="ldr",
                        operands="r3, [r0, #0x0]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x803C,
                        size=4,
                        mnemonic="ldr",
                        operands="r3, [r0]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x8040,
                    size=4,
                    mnemonic="cmp",
                    operands="r3, #0x0",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x8044,
                        size=4,
                        mnemonic="beq",
                        operands="0x8058",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8044,
                        size=4,
                        mnemonic="beq",
                        operands="#0x8058",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
            ],
            0x8058: [
                (
                    Instruction(
                        virtual_address=0x8058,
                        size=4,
                        mnemonic="ldmia",
                        operands="sp!, {r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8058,
                        size=4,
                        mnemonic="ldmia",
                        operands="sp!, {r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8058,
                        size=4,
                        mnemonic="ldmia",
                        operands="sp!, {r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8058,
                        size=4,
                        mnemonic="pop",
                        operands="{r3, lr}",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x805C,
                    size=4,
                    mnemonic="bx",
                    operands="lr",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x8048: [
                (
                    Instruction(
                        virtual_address=0x8048,
                        size=4,
                        mnemonic="ldr",
                        operands="r3, [0x8064]",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8048,
                        size=4,
                        mnemonic="ldr",
                        operands="r3, [pc, #0x14]",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x804C,
                    size=4,
                    mnemonic="cmp",
                    operands="r3, #0x0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8050,
                    size=4,
                    mnemonic="movne",
                    operands="lr, pc",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8054,
                    size=4,
                    mnemonic="bxne",
                    operands="r3",
                    mode=InstructionSetMode.NONE,
                ),
            ],
            0x8068: [
                Instruction(
                    virtual_address=0x8068,
                    size=4,
                    mnemonic="str",
                    operands="r11, [sp, #-0x4]!",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x806C,
                    size=4,
                    mnemonic="add",
                    operands="r11, sp, #0x0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8070,
                    size=4,
                    mnemonic="sub",
                    operands="sp, sp, #0xc",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8074,
                    size=4,
                    mnemonic="str",
                    operands="r0, [r11, #-0x8]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8078,
                    size=4,
                    mnemonic="str",
                    operands="r1, [r11, #-0xc]",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x807C,
                    size=4,
                    mnemonic="mov",
                    operands="r3, #0x0",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8080,
                    size=4,
                    mnemonic="mov",
                    operands="r0, r3",
                    mode=InstructionSetMode.NONE,
                ),
                Instruction(
                    virtual_address=0x8084,
                    size=4,
                    mnemonic="add",
                    operands="sp, r11, #0x0",
                    mode=InstructionSetMode.NONE,
                ),
                (
                    Instruction(
                        virtual_address=0x8088,
                        size=4,
                        mnemonic="ldr",
                        operands="r11, [sp], #0x4",
                        mode=InstructionSetMode.NONE,
                    ),
                    Instruction(
                        virtual_address=0x8088,
                        size=4,
                        mnemonic="pop",
                        operands="{r11}",
                        mode=InstructionSetMode.NONE,
                    ),
                ),
                Instruction(
                    virtual_address=0x808C,
                    size=4,
                    mnemonic="bx",
                    operands="lr",
                    mode=InstructionSetMode.NONE,
                ),
            ],
        },
        set(),  # No optional results
        "simple_arm_gcc.o.elf",
        "c79d1bea0398d7a9d0faa1ba68786f5e",
        {
            0x8018: Range(0x8018, 0x8030),
            0x8034: Range(0x8034, 0x8048),
            0x8058: Range(0x8058, 0x8060),
            0x8048: Range(0x8048, 0x8058),
            0x8068: Range(0x8068, 0x8090),
        },
    ),
]


class BasicBlockUnpackerUnpackAndVerifyPattern(UnpackAndVerifyPattern):
    """
    Test pattern which checks a BasicBlockUnpacker implementation. This pattern is ready to go
    off-the-shelf. All that is needed to use it is
     1) A subclass with the name prefixed with "Test", and
     2) That subclass should be in a pytest context where the supplied frak context will have a
     BasicBlockUnpacker implementation.

    This file includes test cases of the type BasicBlockUnpacker. These include a URL
    which points to a binary which serves as the root resource. This binary will be unpacked
    recursively down to Instructions, and all ComplexBlocks in the .text section will be
    extracted. Those ComplexBlocks should line up with the expected complex block virtual
    addresses; so should all of the BasicBlocks and DataWords that make up that ComplexBlock; and
    so should all of the Instructions in each of those BasicBlocks.
    Each of those are checked for some other specific expected attributes as well.
    """

    async def unpack(self, root_resource: Resource):
        await root_resource.unpack_recursively()

    @pytest.fixture(params=BASIC_BLOCK_UNPACKER_TEST_CASES, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> BasicBlockUnpackerTestCase:
        return request.param

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: BasicBlockUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(TEST_PATTERN_ASSETS_DIR, unpack_verify_test_case.binary_filename)
        with open(asset_path, "rb") as f:
            binary_data = f.read()
        resource = await ofrak_context.create_root_resource(test_id, binary_data, tags=(File,))
        return resource

    async def verify_descendant(
        self, basic_block: BasicBlock, specified_result: List[ExpectedBasicBlockUnpackResult]
    ):
        instructions = await basic_block.get_instructions()

        # Check that the parent complex blocks are extracted as expected
        instructions_by_addr: Dict[int, ExpectedBasicBlockUnpackResult] = dict()
        for expected_instructions in specified_result:
            if type(expected_instructions) is tuple:
                instructions_by_addr[
                    expected_instructions[0].virtual_address
                ] = expected_instructions
            else:
                instructions_by_addr[expected_instructions.virtual_address] = (
                    expected_instructions,
                )

        # Check that all expected basic blocks have been extracted
        expected_vaddr_set = set(instructions_by_addr.keys())
        unpacked_vaddr_set = {instruction.virtual_address for instruction in instructions}
        assert (
            unpacked_vaddr_set == expected_vaddr_set
        ), f"Unpacked vaddrs {unpacked_vaddr_set} does not match expected vaddrs {expected_vaddr_set}"

        errors = []
        for instruction in instructions:
            expected_instructions = instructions_by_addr[instruction.virtual_address]
            # GhidraBasicBlockUnpacker does not provide trustworthy results for
            #  - Instruction.registers_read
            #  - Instruction.registers_written
            sanitized_instruction = Instruction(
                instruction.virtual_address,
                instruction.size,
                instruction.mnemonic,
                instruction.operands,
                instruction.mode,
            )
            sanitized_expected_instructions = tuple(
                Instruction(
                    expected_instr.virtual_address,
                    expected_instr.size,
                    expected_instr.mnemonic,
                    expected_instr.operands,
                    expected_instr.mode,
                )
                for expected_instr in expected_instructions
            )
            if not any(
                sanitized_instruction == sanitized_expected_instr
                for sanitized_expected_instr in sanitized_expected_instructions
            ):
                e = ValueError(
                    f"Extracted instruction at {instruction.virtual_address:x} does not match any "
                    f"of the possible expected results: \n"
                    f"got: {sanitized_instruction}\n"
                    f"expected any of: {sanitized_expected_instructions}"
                )
                errors.append(e)

        if len(errors) > 0:
            raise ValueError(*errors)

    async def get_descendants_to_verify(self, unpacked_resource: Resource) -> Dict[int, Resource]:
        elf = await unpacked_resource.view_as(Elf)
        text_section = await elf.get_section_by_name(".text")
        basic_blocks: List[BasicBlock] = list(
            await text_section.resource.get_descendants_as_view(
                BasicBlock,
                r_filter=ResourceFilter.with_tags(BasicBlock),
                r_sort=ResourceSort(BasicBlock.VirtualAddress),
            )
        )
        return {bb.virtual_address: bb for bb in basic_blocks}
