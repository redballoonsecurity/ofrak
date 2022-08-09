import tempfile
from dataclasses import dataclass
from typing import List

import lief

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak.core.elf.model import Elf
from ofrak_type.range import Range


@dataclass
class LiefAddSegmentConfig(ComponentConfig):
    virtual_address: int
    alignment: int
    content: List[int]
    rwx_flags: str


class LiefAddSegmentModifier(Modifier[LiefAddSegmentConfig]):
    id = b"LiefAddSegmentModifier"
    targets = (Elf,)

    async def modify(self, resource: Resource, config: LiefAddSegmentConfig) -> None:
        binary = lief.parse(await resource.get_data())
        assert binary.has(lief.ELF.SEGMENT_TYPES.NOTE)

        segment = lief.ELF.Segment()
        segment.type = lief.ELF.SEGMENT_TYPES.LOAD
        segment.content = config.content
        segment.alignment = config.alignment
        segment.virtual_address = config.virtual_address
        if "r" in config.rwx_flags:
            segment.add(lief.ELF.SEGMENT_FLAGS.R)
        if "w" in config.rwx_flags:
            segment.add(lief.ELF.SEGMENT_FLAGS.W)
        if "x" in config.rwx_flags:
            segment.add(lief.ELF.SEGMENT_FLAGS.X)
        # segment           = binary.add(segment)
        # instead of adding a segment to the binary, replace a useless NOTE segment
        # based on https://github.com/lief-project/LIEF/issues/98
        segment = binary.replace(segment, binary[lief.ELF.SEGMENT_TYPES.NOTE])
        with tempfile.NamedTemporaryFile() as temp_file:
            binary.write(temp_file.name)
            temp_file.flush()
            with open(temp_file.name, "rb") as f_handle:
                new_data = f_handle.read()
        # replace all old content (old range) with new content from Lief
        resource.queue_patch(Range(0, await resource.get_data_length()), new_data)
