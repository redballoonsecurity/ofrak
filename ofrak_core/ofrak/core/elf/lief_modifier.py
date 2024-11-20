import tempfile
from dataclasses import dataclass
from typing import List, Optional

import lief

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak.core.elf.model import Elf
from ofrak_type.range import Range


@dataclass
class LiefAddSegmentConfig(ComponentConfig):
    """
    Config for the [LiefAddSegmentModifier][ofrak.core.elf.lief_modifier.LiefAddSegmentModifier].

    :ivar virtual_address: virtual address of the new segment
    :ivar alignment: alignment of the new segment
    :ivar content: list of integers representing the raw bytes of the new segment
    :ivar rwx_flags: string representation of the new segment's R/W/X permissions
    :ivar replace_note: replace the unused NOTE segment with the new segment, rather than adding a
    new segment. defaults to `True`, as adding a new segment may corrupt the ELF due to a LIEF bug.
    :ivar physical_address: overwrite the default physical address (defaults to the virtual address)
    """

    virtual_address: int
    alignment: int
    content: List[int]
    rwx_flags: str
    replace_note: bool = True
    physical_address: Optional[int] = None


class LiefAddSegmentModifier(Modifier[LiefAddSegmentConfig]):
    id = b"LiefAddSegmentModifier"
    targets = (Elf,)

    async def modify(self, resource: Resource, config: LiefAddSegmentConfig) -> None:
        binary: lief.ELF.Binary = lief.parse(await resource.get_data())

        segment = lief.ELF.Segment()
        segment.type = lief.ELF.SEGMENT_TYPES.LOAD
        segment.content = config.content
        segment.alignment = config.alignment
        segment.virtual_address = config.virtual_address
        if config.physical_address is not None:
            segment.physical_address = config.physical_address
        if "r" in config.rwx_flags:
            segment.add(lief.ELF.SEGMENT_FLAGS.R)
        if "w" in config.rwx_flags:
            segment.add(lief.ELF.SEGMENT_FLAGS.W)
        if "x" in config.rwx_flags:
            segment.add(lief.ELF.SEGMENT_FLAGS.X)

        if config.replace_note:
            # instead of adding a segment to the binary, replace a useless NOTE segment
            #   see https://github.com/lief-project/LIEF/issues/98
            #   and https://github.com/lief-project/LIEF/issues/143
            if not binary.has(lief.ELF.SEGMENT_TYPES.NOTE):
                raise ValueError("Binary must have a NOTE section to add a new section")
            segment = binary.replace(segment, binary[lief.ELF.SEGMENT_TYPES.NOTE])
            if config.physical_address is not None:
                segment.physical_address = config.physical_address
        else:
            _ = binary.add(segment)

        with tempfile.NamedTemporaryFile() as temp_file:
            binary.write(temp_file.name)
            temp_file.flush()
            with open(temp_file.name, "rb") as f_handle:
                new_data = f_handle.read()
        # replace all old content (old range) with new content from Lief
        resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


@dataclass
class LiefAddSectionModifierConfig(ComponentConfig):
    name: str
    content: bytes
    flags: int


class LiefAddSectionModifer(Modifier[LiefAddSectionModifierConfig]):
    targets = (Elf,)

    async def modify(self, resource: Resource, config: LiefAddSectionModifierConfig):
        binary: lief.ELF.Binary = lief.parse(await resource.get_data())
        section: lief.ELF.Section = lief.ELF.Section()
        section.name = config.name
        section.content = list(config.content)
        section.flags = config.flags
        binary.add(section)

        with tempfile.NamedTemporaryFile() as temp_file:
            binary.write(temp_file.name)
            temp_file.flush()
            with open(temp_file.name, "rb") as f_handle:
                new_data = f_handle.read()
        # replace all old content (old range) with new content from Lief
        resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


@dataclass
class LiefRemoveSectionModifierConfig(ComponentConfig):
    name: str


class LiefRemoveSectionModifier(Modifier[LiefRemoveSectionModifierConfig]):
    targets = (Elf,)

    async def modify(self, resource: Resource, config: LiefRemoveSectionModifierConfig):
        binary: lief.ELF.Binary = lief.parse(await resource.get_data())
        section: lief.ELF.Section = binary.get_section(config.name)
        if section is None:
            raise AttributeError(f"No section with name {config.name}")
        binary.remove(section)

        with tempfile.NamedTemporaryFile() as temp_file:
            binary.write(temp_file.name)
            temp_file.flush()
            with open(temp_file.name, "rb") as f_handle:
                new_data = f_handle.read()
        # replace all old content (old range) with new content from Lief
        resource.queue_patch(Range(0, await resource.get_data_length()), new_data)
