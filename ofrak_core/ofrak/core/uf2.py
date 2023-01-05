import logging
import struct
from enum import IntEnum
from dataclasses import dataclass
from typing import List, Tuple
from ofrak.core.code_region import CodeRegion

from ofrak.resource import Resource
from ofrak.model.resource_model import ResourceAttributes
from ofrak.component.unpacker import Unpacker
from ofrak.component.packer import Packer
from ofrak.component.identifier import Identifier
from ofrak.core.binary import GenericBinary
from ofrak_type.range import Range
from ofrak.service.resource_service_i import ResourceFilter

LOGGER = logging.getLogger(__name__)

UF2_MAGIC_START_ONE = 0x0A324655
UF2_MAGIC_START_TWO = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30

HEADER_LENGTH = 32
DATA_LENGTH = 476


@dataclass
class Uf2File(GenericBinary):
    """
    A UF2 file
    """


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Uf2FileAttributes(ResourceAttributes):
    """
    Remembers all the information needed to repack that can't be deduced from the contents.
    """

    family_id: int


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Uf2BlockHeader(ResourceAttributes):
    """
    Recreates the official spec

    Offset  Size    Value
    0       4       First magic number, 0x0A324655 ("UF2\n")
    4       4       Second magic number, 0x9E5D5157
    8       4       Flags
    12      4       Address in flash where the data should be written
    16      4       Number of bytes used in data (often 256)
    20      4       Sequential block number; starts at 0
    24      4       Total number of blocks in file
    28      4       File size or board family ID or zero
    32      476     Data, padded with zeros
    508     4       Final magic number, 0x0AB16F30
    """

    flags: int
    target_addr: int
    payload_size: int
    block_no: int
    num_blocks: int
    filesize_family_id: int


class Uf2Flags(IntEnum):
    NOT_MAIN_FLASH = 0x1
    FILE_CONTAINER = 0x1000
    FAMILY_ID_PRESENT = 0x2000
    MD5_CHECKSUM_PRESENT = 0x4000
    EXTENSION_TAGS_PRESENT = 0x8000


class Uf2Unpacker(Unpacker[None]):
    """
    UF2 unpacker.

    Extracts the data from a UF2 packed file.
    """

    targets = (Uf2File,)
    children = (CodeRegion,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack a UF2 file.

        UF2 files contain blocks of binary data.
        """
        data_length = await resource.get_data_length()

        ranges: List[Tuple[Range, bytes]] = []

        # block_no are 0 indexed, to make the check do one fewer check, we start at -1
        previous_block_no = -1
        family_id = None
        file_num_blocks = None
        block_no = 0

        for i in range(0, data_length, 512):
            data = await resource.get_data(Range(i, (i + 512)))
            (
                magic_start_one,
                magic_start_two,
                flags,
                target_addr,
                payload_size,
                block_no,
                num_blocks,
                filesize_familyID,
                payload_data,
                magic_end,
            ) = struct.unpack("8I476sI", data)

            # basic sanity checks
            if magic_start_one != UF2_MAGIC_START_ONE:
                raise ValueError("Bad Start Magic")
            if magic_start_two != UF2_MAGIC_START_TWO:
                raise ValueError("Bad Start Magic")
            if magic_end != UF2_MAGIC_END:
                raise ValueError("Bad End Magic")

            if (previous_block_no - block_no) != -1:
                raise ValueError("Skipped a block number")
            previous_block_no = block_no

            if not file_num_blocks:
                file_num_blocks = num_blocks

            if family_id is None:
                family_id = filesize_familyID
            else:
                if family_id != filesize_familyID:
                    raise NotImplementedError("Multiple family IDs in file not supported")

            # unpack data
            if flags & Uf2Flags.NOT_MAIN_FLASH:
                # data not written to main flash
                raise NotImplementedError(
                    "Data not written to main flash is currently not supported"
                )
            elif flags & Uf2Flags.FILE_CONTAINER:
                # file container
                raise NotImplementedError("File containers are currently not implemented")
            elif flags & Uf2Flags.FAMILY_ID_PRESENT:
                data = payload_data[0:payload_size]
                if len(ranges) == 0:
                    ranges.append((Range(target_addr, target_addr + payload_size), data))
                else:
                    last_region_range, last_region_data = ranges[-1]

                    # if range is adjacent, extend, otherwise start a new one
                    if target_addr - last_region_range.end == 0:
                        last_region_range.end = target_addr + payload_size
                        last_region_data += data
                        ranges[-1] = (last_region_range, last_region_data)
                    else:
                        ranges.append((Range(target_addr, target_addr + payload_size), data))
            else:
                # unsupported flags
                raise ValueError(f"Unsupported flags {flags}")

        # count vs 0 indexed (there are 256 blocks from 0-255)
        if file_num_blocks != (block_no + 1):
            raise ValueError(
                f"Incorrect number of blocks. Expected {file_num_blocks}, got {block_no}"
            )

        if family_id:
            file_attributes = Uf2FileAttributes(family_id)
            resource.add_attributes(file_attributes)

        # print("num: ", last_block_no, "file: ", file_num_blocks)
        # assert last_block_no == file_num_blocks, "Did not unpack enough blocks"

        for flash_range, flash_data in ranges:
            await resource.create_child_from_view(
                CodeRegion(flash_range.start, flash_range.end - flash_range.start),
                data=flash_data,
            )


class Uf2FilePacker(Packer[None]):
    """
    Pack a resource into the UF2 file format
    """

    id = b"Uf2FilePacker"
    targets = (Uf2File,)

    async def pack(self, resource: Resource, config=None):
        """
        Pack a resource into a UF2 file

        :param resource:
        :param config:
        """

        payloads: List[Tuple[int, int, bytes]] = []  # List of target_addr, payload_data

        for memory_region_r in await resource.get_children(
            r_filter=ResourceFilter(
                tags=(CodeRegion,),
            )
        ):
            memory_region = await memory_region_r.view_as(CodeRegion)
            data = await memory_region_r.get_data()
            data_length = await memory_region_r.get_data_length()
            data_range = memory_region.vaddr_range()
            addr = data_range.start

            for i in range(0, data_length, 256):
                payloads.append((addr + i, 256, data[i : (i + 256)]))
                continue

        num_blocks = len(payloads)
        block_no = 0

        file_attributes = resource.get_attributes(attributes_type=Uf2FileAttributes)
        family_id = file_attributes.family_id

        repacked_data = b""

        for target_addr, payload_size, payload_data in payloads:
            repacked_data += struct.pack(
                "8I476sI",
                UF2_MAGIC_START_ONE,
                UF2_MAGIC_START_TWO,
                Uf2Flags.FAMILY_ID_PRESENT,
                target_addr,
                payload_size,
                block_no,
                num_blocks,
                family_id,
                payload_data + b"\x00" * (467 - payload_size),  # add padding
                UF2_MAGIC_END,
            )
            block_no += 1

        resource.queue_patch(Range(0, await resource.get_data_length()), repacked_data)


class Uf2FileIdentifier(Identifier):
    id = b"Uf2FileIdentifier"
    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config=None):
        resource_data = await resource.get_data(Range(0, 8))
        if resource_data[:4] == UF2_MAGIC_START_ONE and resource_data[4:8] == UF2_MAGIC_START_TWO:
            resource.add_tag(Uf2File)
