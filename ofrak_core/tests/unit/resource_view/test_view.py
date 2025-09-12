from dataclasses import dataclass
from typing import Optional

import pytest

from ofrak import OFRAKContext, ResourceAttributes
from ofrak.core import InstructionModifier, InstructionModifierConfig
from ofrak.core.addressable import Addressable
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.basic_block import BasicBlock
from ofrak.core.instruction import Instruction
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.program import Program
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter
from ofrak.core.free_space import (
    FreeSpaceModifier,
    FreeSpaceModifierConfig,
)
from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    InstructionSetMode,
    ProcessorType,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range
from ..model import FlattenedResource

MOCK_INSTRUCTION_MACHINE_CODE = b"\x03\x10\x82\xe0"


@dataclass
class MockProgram(ResourceView):
    isa: InstructionSet
    sub_isa: Optional[SubInstructionSet]
    bit_width: BitWidth
    endianness: Endianness
    processor: Optional[ProcessorType]


@pytest.fixture
def mock_instruction():
    return FlattenedResource(
        (Instruction,),
        (
            AttributesType[Addressable](0x100),
            AttributesType[MemoryRegion](
                0x4,
            ),
            AttributesType[Instruction](
                "add",
                "r1, r2, r3",
                InstructionSetMode.NONE,
            ),
        ),
        data=MOCK_INSTRUCTION_MACHINE_CODE,
    )


@pytest.fixture
def mock_instruction_view():
    return Instruction(
        0x100,
        0x4,
        "add",
        "r1, r2, r3",
        InstructionSetMode.NONE,
    )


@pytest.fixture
def mock_basic_block():
    return FlattenedResource(
        (BasicBlock, MemoryRegion, MockProgram),
        (
            AttributesType[Addressable](0x100),
            AttributesType[MemoryRegion](
                0x10,
            ),
            AttributesType[BasicBlock](
                InstructionSetMode.NONE,
                False,
                None,
            ),
            AttributesType[MockProgram](
                InstructionSet.ARM,
                None,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                None,
            ),
        ),
        data=bytes(0x10),
    )


async def test_create_from_resource(mock_instruction, ofrak_context):
    instr_r, _ = await mock_instruction.inflate(ofrak_context)
    instr_view = await instr_r.view_as(Instruction)


async def test_create_resource_from_view(mock_basic_block, mock_instruction_view, ofrak_context):
    bb_r, _ = await mock_basic_block.inflate(ofrak_context)
    instr_view = mock_instruction_view
    instr_view.data = MOCK_INSTRUCTION_MACHINE_CODE

    assert instr_view.data == MOCK_INSTRUCTION_MACHINE_CODE

    instr_r = await bb_r.create_child_from_view(instr_view, data_range=Range(0x0, 0x4))

    assert instr_r.get_attributes(AttributesType[Instruction]) is not None
    assert instr_r.get_attributes(AttributesType[MemoryRegion]) is not None
    assert instr_r.get_attributes(AttributesType[Addressable]) is not None
    bb_children = list(await bb_r.get_children())
    assert len(bb_children) == 1


async def test_create_view_from_resource(mock_instruction, mock_instruction_view, ofrak_context):
    instr_r, _ = await mock_instruction.inflate(ofrak_context)
    new_instr_view = await instr_r.view_as(Instruction)

    assert new_instr_view.virtual_address == mock_instruction_view.virtual_address
    assert new_instr_view.size == mock_instruction_view.size
    assert new_instr_view.mnemonic == mock_instruction_view.mnemonic
    assert new_instr_view.operands == mock_instruction_view.operands
    assert new_instr_view.mode == mock_instruction_view.mode


async def test_view_indexes_types():
    assert Instruction.VirtualAddress.attributes_owner is AttributesType[Addressable]
    assert Instruction.Size.attributes_owner is AttributesType[MemoryRegion]
    assert Instruction.Mnemonic.attributes_owner is AttributesType[Instruction]


async def test_view_indexes(mock_basic_block, mock_instruction_view, ofrak_context):
    bb_r, _ = await mock_basic_block.inflate(ofrak_context)
    instr_view = mock_instruction_view

    instr_r = await bb_r.create_child_from_view(instr_view)

    # Attribute filter by index in ResourceView
    bb_children = list(
        await bb_r.get_children(
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(Instruction.VirtualAddress, 0x100),)
            )
        )
    )
    assert len(bb_children) == 1

    # Attribute filter by index in ResourceView superclass
    bb_children = list(
        await bb_r.get_children(
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x100),)
            )
        )
    )
    assert len(bb_children) == 1

    # Attribute filter by index in ResourceView's attribute type
    bb_children = list(
        await bb_r.get_children(
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x100),)
            )
        )
    )
    assert len(bb_children) == 1

    # Check for false positive (filter should not match any)
    bb_children = list(
        await bb_r.get_children(
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, 0x102),)
            )
        )
    )
    assert len(bb_children) == 0

    # Filter by some other attribute
    bb_children = list(
        await bb_r.get_children(
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(Instruction.Mnemonic, "add"),)
            )
        )
    )
    assert len(bb_children) == 1

    # Another false positive check
    bb_children = list(
        await bb_r.get_children(
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(Instruction.Mnemonic, "deadd"),)
            )
        )
    )
    assert len(bb_children) == 0


async def test_AttributesType():
    # Constructor fails without a type parameter
    with pytest.raises(NotImplementedError):
        AttributesType()

    # With a type parameter, the constructor of an actual attribute is used
    _ = AttributesType[Instruction](
        "add",
        "r1, r2, r3",
        InstructionSetMode.NONE,
    )

    # We get a ResourceAttributes type (the expected type) from AttributesType
    instr_attrs_t = AttributesType[Instruction]
    assert issubclass(instr_attrs_t, ResourceAttributes)
    assert instr_attrs_t.__name__ == "AttributesType[Instruction]"
    assert AttributesType[Instruction] is instr_attrs_t


@pytest.fixture()
async def instr_view(ofrak_context: OFRAKContext):
    instr_r = await ofrak_context.create_root_resource(
        "test_instruction",
        b"\x00" * 4,
        (Instruction,),
    )
    instr_r.add_view(Instruction(0x100, 0x4, "", "", InstructionSetMode.NONE))
    instr_r.add_attributes(
        ProgramAttributes(
            InstructionSet.ARM,
            None,
            BitWidth.BIT_32,
            Endianness.LITTLE_ENDIAN,
            None,
        ),
    )
    await instr_r.save()

    return await instr_r.view_as(Instruction)


async def test_resource_property_does_not_modify(instr_view: Instruction):
    await instr_view.resource.run(
        InstructionModifier, InstructionModifierConfig("add", "r4, r5", InstructionSetMode.NONE)
    )

    new_instr_view = await instr_view.resource.view_as(Instruction)

    assert new_instr_view.mnemonic == "add"
    assert new_instr_view.operands == "r4, r5"


async def test_modifier_updates_view(instr_view: Instruction):
    await instr_view.resource.run(
        InstructionModifier, InstructionModifierConfig("add", "r4, r5", InstructionSetMode.NONE)
    )

    assert instr_view.mnemonic == "add"
    assert instr_view.operands == "r4, r5"


async def test_save_updates_view(instr_view: Instruction):
    instr_view.resource.add_view(Instruction(0x100, 0x4, "sub", "r4, r5", InstructionSetMode.NONE))
    await instr_view.resource.save()

    assert instr_view.mnemonic == "sub"


async def test_resource_view_delete_resource(ofrak_context: OFRAKContext):
    root_r = await ofrak_context.create_root_resource(
        "mock_memory_region",
        b"\xff" * 0x10,
        (Program, MemoryRegion),
    )
    root_r.add_attributes(
        ProgramAttributes(InstructionSet.ARM, None, BitWidth.BIT_32, Endianness.LITTLE_ENDIAN, None)
    )
    root_r.add_view(MemoryRegion(0x10, 0x10))
    await root_r.save()
    region_r = await root_r.create_child_from_view(
        MemoryRegion(0x10, 0x10),
        data_range=Range(0, 0x10),
    )
    region_view = await region_r.view_as(MemoryRegion)

    await region_view.resource.run(FreeSpaceModifier, FreeSpaceModifierConfig(MemoryPermissions.RX))

    with pytest.raises(ValueError):
        _ = region_view.resource
