import logging
from itertools import tee
from typing import List

from ofrak import Modifier, Resource, OFRAKContext
from ofrak.core import (
    Elf,
    FreeSpace,
    ElfProgramHeaderModifier,
    ElfProgramHeaderModifierConfig,
    Allocatable,
    ElfProgramHeader,
    ElfProgramHeaderType,
    ElfUnpacker,
)
from ofrak_type import Range


LOGGER = logging.getLogger()


class ElfLoadAlignmentModifier(Modifier[None]):
    """
    Reclaim unused alignment bytes between adjacent PT_LOAD segment in an ELF and tag them as free space.

    Inspired by Silvio Cesare's padding infection technique, this modifier capitalizes on the fact that the alignment
    bytes that exist between PT_LOAD sections in ELF binaries. These alignment bytes are added to the preceding PT_LOAD
    segment.

    Use this modifier if these alignment bytes provide enough space for your planned binary modifications.

    For more information on Silvio's padding infection technique, see:
    - The [original paper](https://web.archive.org/web/20130820033847/http://vxheaven.org/lib/vsc01.html)
    - Chapter 4 of Ryan "elfmaster" O'Neill's "Learning Linux Binary Analysis".
    """

    targets = (Elf,)

    async def modify(self, resource: Resource, config=None) -> None:
        """
        Scan target ELF for unused alignment bytes between PT_LOAD segment, extend preceding segment to include these
        bytes, and tag them as FreeSpace.
        """
        elf: Elf = await resource.view_as(Elf)
        load_program_headers = list(await get_load_program_headers(elf))
        # First, get program headers sorted by file offset
        load_program_headers_by_offset = sorted(load_program_headers, key=lambda x: x.p_offset)
        found_space = False
        for first_program_header, second_program_header in _pairwise(
            load_program_headers_by_offset
        ):
            if first_program_header.p_filesz != first_program_header.p_memsz:
                # Avoid overwriting .bss in data segments or other weird things that change size
                continue
            first_header_range = Range.from_size(
                first_program_header.p_offset, first_program_header.p_filesz
            )
            second_header_range = Range.from_size(
                second_program_header.p_offset, second_program_header.p_filesz
            )
            potential_free_space = second_header_range.start - first_header_range.end
            if potential_free_space <= 0:
                # No free space exists on disk
                continue
            found_space = True
            LOGGER.info(
                f"Found {hex(potential_free_space)} of free space between {first_program_header}and"
                f"{second_program_header}"
            )
            trimmed_potential_free_space = await self._trim_potential_free_space_by_vaddr(
                first_program_header, load_program_headers_by_offset, potential_free_space
            )
            free_space = FreeSpace(
                first_program_header.p_vaddr + first_program_header.p_memsz,
                trimmed_potential_free_space,
                first_program_header.get_memory_permissions(),
            )
            LOGGER.info(f"Creating {free_space} in {resource}")
            await resource.create_child_from_view(
                free_space,
                data_range=Range.from_size(first_header_range.end, trimmed_potential_free_space),
            )
            await first_program_header.resource.run(
                ElfProgramHeaderModifier,
                ElfProgramHeaderModifierConfig(
                    p_filesz=first_program_header.p_filesz + trimmed_potential_free_space,
                    p_memsz=first_program_header.p_filesz + trimmed_potential_free_space,
                ),
            )
        if found_space:
            # Tag ELF as Allocatable so FreeSpace can be used
            resource.add_tag(Allocatable)

    @staticmethod
    async def _trim_potential_free_space_by_vaddr(
        first_program_header: ElfProgramHeader,
        load_program_headers_by_offset: List[ElfProgramHeader],
        offset_difference: int,
    ) -> int:
        """
        Check that the potential free space does not overlap with any existing PT_LOAD segments.
        If there is overlap, trim the potential free space.
        """
        vaddr_ranges = Range.merge_ranges(
            [
                Range.from_size(header.p_vaddr, header.p_memsz)
                for header in load_program_headers_by_offset
            ]
        )
        # Reduce size based on vaddr constraints
        potential_free_space_range = Range.from_size(
            first_program_header.p_vaddr + first_program_header.p_memsz, offset_difference
        )
        for vaddr_range in vaddr_ranges:
            if potential_free_space_range.overlaps(vaddr_range):
                potential_free_space_range = _crop_range(potential_free_space_range, vaddr_range)
        return potential_free_space_range.length()


async def get_load_program_headers(elf: Elf) -> List[ElfProgramHeader]:
    load_program_headers = list()
    for program_header in await elf.get_program_headers():
        if program_header.p_type == ElfProgramHeaderType.LOAD.value:
            load_program_headers.append(program_header)
    return load_program_headers


def _crop_range(range_1: Range, range_2: Range) -> Range:
    """
    Split range_1 around range_2 and return the split range whose start is the same as range_1.
    """
    splits = range_1.split(range_2)
    for s in splits:
        if s.start == range_1.start:
            return s
    raise ValueError(
        f"Error removing intersection between {range_1} and {range_2} from {range_1}. "
        f"This should be unreachable."
    )


def _pairwise(iterable):
    """
    A helper function waiting for itertools.pairwise from Python 3.10:
    https://docs.python.org/3/library/itertools.html#itertools.pairwise.

    Usage: `_pairwise('ABCDEFG') --> AB BC CD DE EF FG`
    """
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


async def main(ofrak_context: OFRAKContext, file: str, output_file: str):
    root_resource = await ofrak_context.create_root_resource_from_file(file)
    await root_resource.identify()
    await root_resource.run(ElfUnpacker)
    await root_resource.run(ElfLoadAlignmentModifier)
    if root_resource.has_tag(Allocatable):
        allocatable = await root_resource.view_as(Allocatable)
        print(f"[+] Free space found by ElfLoadAlignmentFreeSpaceModifier: {allocatable}")
        for key, value in allocatable.free_space_ranges.items():
            print(f"[+] {key} free space: {hex(sum([v.length() for v in value]))} bytes")
        # print(f"[+] Fre space by permissions: {}")
        await root_resource.flush_to_disk(output_file)
        print(f"[+] Output file written to {output_file}")
    else:
        print("[+] No free space found")


if __name__ == "__main__":
    import argparse

    from ofrak import OFRAK

    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f")
    parser.add_argument("--output-file", "-o")
    args = parser.parse_args()
    ofrak = OFRAK()
    ofrak.run(main, args.file, args.output_file)  # type: ignore
