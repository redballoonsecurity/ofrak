import asyncio

from ofrak import Modifier, Resource
from ofrak.core import (
    Elf,
    ElfProgramHeaderModifier,
    ElfProgramHeaderModifierConfig,
    ElfProgramHeaderType,
    FreeSpace,
    Allocatable,
)
from ofrak_type import Range


class ElfExtendFirstLoadSegmentModifier(Modifier[None]):
    targets = (Elf,)

    async def modify(self, resource: Resource, config=None) -> None:
        used_space = Range.merge_ranges(
            await asyncio.gather(
                *(
                    c.get_data_range_within_parent()
                    for c in await resource.get_children()
                    if c.get_data_id()
                )
            )
        )
        unused_space = []
        for i in range(len(used_space) - 1):
            first, second = used_space[i], used_space[i + 1]
            unused_space.append(Range(first.end, second.start))

        elf = await resource.view_as(Elf)
        program_headers = await elf.get_program_headers()
        first_program_header = list(sorted(program_headers, key=lambda p: p.p_offset))[0]
        load_segment_offset_ranges = Range.merge_ranges(
            Range.from_size(seg.p_offset, seg.p_filesz)
            for seg in program_headers
            if seg.p_type == ElfProgramHeaderType.LOAD.value
        )

        if first_program_header.p_offset == 0:
            raise RuntimeError("ELF already has LOAD segment that maps offset 0.")

        new_load_range = Range(0, first_program_header.p_offset)
        free_space = [
            space.intersect(new_load_range)
            for space in unused_space
            if new_load_range.overlaps(space)
            and not any(space.overlaps(load_segment) for load_segment in load_segment_offset_ranges)
        ]
        if len(free_space) == 0:
            raise RuntimeError("First LOAD segment cannot be made to intersect any free space.")

        for space in free_space:
            await resource.create_child_from_view(
                FreeSpace(
                    first_program_header.p_vaddr - first_program_header.p_offset + space.start,
                    first_program_header.p_offset - space.start,
                    first_program_header.get_memory_permissions(),
                ),
                data_range=space,
            )
        resource.add_tag(Allocatable)
        await resource.save()

        await first_program_header.resource.run(
            ElfProgramHeaderModifier,
            ElfProgramHeaderModifierConfig(
                p_offset=0,
                p_vaddr=first_program_header.p_vaddr - first_program_header.p_offset,
                p_paddr=(
                    first_program_header.p_vaddr - first_program_header.p_offset
                    if first_program_header.p_paddr != 0
                    else 0
                ),
                p_filesz=first_program_header.p_filesz + first_program_header.p_offset,
                p_memsz=first_program_header.p_memsz + first_program_header.p_offset,
                p_align=0,
            ),
        )
