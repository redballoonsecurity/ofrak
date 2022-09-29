import io
import logging
import struct
from dataclasses import dataclass

from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.model.resource_model import ResourceAttributes
from ofrak.component.unpacker import Unpacker
from ofrak.component.packer import Packer
from ofrak.component.identifier import Identifier
from ofrak.component.analyzer import Analyzer
from ofrak.core.binary import GenericBinary
from ofrak_type.range import Range
from ofrak_type.endianness import Endianness
from ofrak_io.deserializer import BinaryDeserializer
from ofrak.model.resource_model import index
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


@dataclass
class Uf2Block(ResourceView):
    """
    A UF2 block in a UF2 file
    """


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

    @index
    def BlockNo(self) -> int:
        return self.block_no


@dataclass
class Uf2BlockData(GenericBinary):
    """
    Data in the payload section of a UF2 block
    """


class Uf2Unpacker(Unpacker[None]):
    """
    UF2 unpacker.

    Extracts the data from a UF2 packed file.
    """

    targets = (Uf2File,)
    children = (Uf2Block,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack a UF2 file.

        UF2 files contain blocks of binary data.
        """
        data_length = await resource.get_data_length()

        for i in range(0, data_length, 512):
            block_r = await resource.create_child(tags=(Uf2Block,), data_range=Range(i, i + 512))
            block_attributes = await block_r.analyze(Uf2BlockHeader)
            block_r.add_attributes(block_attributes)


class Uf2BlockUnpacker(Unpacker[None]):
    """
    UF2 Block unpacker.

    Extracts the data from a UF2 Block.
    """

    targets = (Uf2Block,)
    children = (Uf2BlockData,)

    async def unpack(self, resource: Resource, config=None):
        await resource.create_child(
            tags=(Uf2BlockData,), data_range=Range(HEADER_LENGTH, HEADER_LENGTH + DATA_LENGTH)
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
        repacked_data = b""

        for uf2_block in await resource.get_children(
            r_filter=ResourceFilter(
                tags=(Uf2Block,),
            )
        ):
            uf2_data = await uf2_block.get_data()
            repacked_data += uf2_data


class Uf2BlockPacker(Packer[None]):
    """
    Pack a resource into the UF2 file format
    """

    id = b"Uf2BlockPacker"
    targets = (Uf2Block,)

    async def pack(self, resource: Resource, config=None):
        repacked_data = b""

        attributes = resource.get_attributes(Uf2BlockHeader)
        header_data = struct.pack(
            "8I",
            UF2_MAGIC_START_ONE,
            UF2_MAGIC_START_TWO,
            attributes.flags,
            attributes.target_addr,
            attributes.payload_size,
            attributes.block_no,
            attributes.num_blocks,
            attributes.filesize_family_id,
        )

        payload = await resource.get_only_child()
        payload_data = await payload.get_data()

        repacked_data += header_data
        repacked_data += payload_data
        repacked_data += bytes(UF2_MAGIC_END)

        LOGGER.info(repacked_data)


class Uf2BlockAnalyzer(Analyzer[None, Uf2BlockHeader]):
    """
    Analyze the Uf2Blocks of a Uf2File
    """

    targets = (Uf2Block,)
    outputs = (Uf2BlockHeader,)

    async def analyze(self, resource: Resource, config=None) -> Uf2BlockHeader:
        data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(data),
            endianness=Endianness.LITTLE_ENDIAN,
            word_size=4,
        )

        deserialized = deserializer.unpack_multiple("8I476sI")
        (
            magic_start_one,
            magic_start_two,
            flags,
            target_addr,
            payload_size,
            block_no,
            num_blocks,
            filesize_familyID,
            data,
            magic_end,
        ) = deserialized

        assert magic_start_one == UF2_MAGIC_START_ONE
        assert magic_start_two == UF2_MAGIC_START_TWO
        assert magic_end == UF2_MAGIC_END

        return Uf2BlockHeader(
            flags,
            target_addr,
            payload_size,
            block_no,
            num_blocks,
            filesize_familyID,
        )


class Uf2FileIdentifier(Identifier):
    id = b"Uf2FileIdentifier"
    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config=None):
        resource_data = await resource.get_data(Range(0, 8))
        if resource_data[:4] == UF2_MAGIC_START_ONE and resource_data[4:8] == UF2_MAGIC_START_TWO:
            resource.add_tag(Uf2File)
