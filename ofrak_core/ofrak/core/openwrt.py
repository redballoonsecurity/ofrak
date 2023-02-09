import io
import struct
import zlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

from ofrak.component.identifier import Identifier
from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_type.endianness import Endianness
from ofrak_type.range import Range

OPENWRT_TRX_MAGIC_BYTES = b"HDR0"
(OPENWRT_TRX_MAGIC_START,) = struct.unpack("<I", OPENWRT_TRX_MAGIC_BYTES)
OPENWRT_TRXV1_HEADER_LEN = 28
OPENWRT_TRXV2_HEADER_LEN = 32
OPENWRT_TRX_MARK = struct.pack(">I", 0xDEADC0DE)


#####################
#       Enums       #
#####################
class OpenWrtTrxVersion(Enum):
    VERSION1 = 1
    VERSION2 = 2


#####################
#     RESOURCES     #
#####################
@dataclass
class OpenWrtTrxHeader(ResourceView):
    """
    OpenWrt trx header
    Information from <https://openwrt.org/docs/techref/headers>
    ```
    TRX v1
     0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------------------------------------------------------+
     |                     magic number ('HDR0')                     |
     +---------------------------------------------------------------+
     |                  length (header size + data)                  |
     +---------------+---------------+-------------------------------+
     |                       32-bit CRC value                        |
     +---------------+---------------+-------------------------------+
     |           TRX flags           |          TRX version          |
     +-------------------------------+-------------------------------+
     |                      Partition offset[0]                      |
     +---------------------------------------------------------------+
     |                      Partition offset[1]                      |
     +---------------------------------------------------------------+
     |                      Partition offset[2]                      |
     +---------------------------------------------------------------+

    TRX v2
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +---------------------------------------------------------------+
     |                     magic number ('HDR0')                     |
     +---------------------------------------------------------------+
     |                  length (header size + data)                  |
     +---------------+---------------+-------------------------------+
     |                       32-bit CRC value                        |
     +---------------+---------------+-------------------------------+
     |           TRX flags           |          TRX version          |
     +-------------------------------+-------------------------------+
     |                      Partition offset[0]                      |
     +---------------------------------------------------------------+
     |                      Partition offset[1]                      |
     +---------------------------------------------------------------+
     |                      Partition offset[2]                      |
     +---------------------------------------------------------------+
     |                      Partition offset[3]                      |
     +---------------------------------------------------------------+
    ```
    """

    trx_magic: int
    trx_length: int
    trx_crc: int
    trx_flags: int
    trx_version: int
    trx_partition_offsets: List[int]

    def get_version(self) -> OpenWrtTrxVersion:
        return OpenWrtTrxVersion(self.trx_version)

    def get_header_length(self) -> int:
        if self.get_version() == OpenWrtTrxVersion.VERSION1:
            return OPENWRT_TRXV1_HEADER_LEN
        elif self.get_version() == OpenWrtTrxVersion.VERSION2:
            return OPENWRT_TRXV2_HEADER_LEN
        else:
            raise ValueError(f"Unknown OpenWrt TRX version: {self.trx_version}")


@dataclass
class OpenWrtTrx(GenericBinary):
    """
    OpenWrtTrx is a TRX binary update for OpenWrt firmware.

    TRX binaries are used for upgrading the firmware of devices already running OpenWrt firmware

    The OpenWrtTrx consists of 1 OpenWrtTrxHeader and 3 or 4 partition(s).
    """

    async def get_header(self) -> OpenWrtTrxHeader:
        return await self.resource.get_only_child_as_view(
            OpenWrtTrxHeader, ResourceFilter.with_tags(OpenWrtTrxHeader)
        )


####################
#    IDENTIFIER    #
####################


class OpenWrtIdentifier(Identifier[None]):
    targets = (
        File,
        GenericBinary,
    )

    async def identify(self, resource: Resource, config=None) -> None:
        trx_magic = await resource.get_data(range=Range(0, 4))
        if trx_magic == OPENWRT_TRX_MAGIC_BYTES:
            resource.add_tag(OpenWrtTrx)


####################
#    UNPACKERS     #
####################
class OpenWrtTrxUnpacker(Unpacker[None]):
    """
    Unpack an OpenWrtTrx firmware file into its partitions.

    The header has a mapped data range, whereas all partitions are unmapped data.
    """

    id = b"OpenWrtTrxUnpacker"
    targets = (OpenWrtTrx,)
    children = (
        OpenWrtTrxHeader,
        GenericBinary,
    )

    async def unpack(self, resource: Resource, config=None):
        data = await resource.get_data()
        # Peek into TRX version to know how big the header is
        trx_version = OpenWrtTrxVersion(struct.unpack("<H", data[14:16])[0])

        if trx_version not in [OpenWrtTrxVersion.VERSION1, OpenWrtTrxVersion.VERSION2]:
            raise UnpackerError(f"Unknown OpenWrt TRX version: {trx_version}")

        header_len = (
            OPENWRT_TRXV1_HEADER_LEN
            if trx_version == OpenWrtTrxVersion.VERSION1
            else OPENWRT_TRXV2_HEADER_LEN
        )
        trx_header_r = await resource.create_child(
            tags=(OpenWrtTrxHeader,), data_range=Range(0, header_len)
        )

        trx_header = await trx_header_r.view_as(OpenWrtTrxHeader)
        partition_offsets = trx_header.trx_partition_offsets

        for i, offset in enumerate(partition_offsets):
            if offset == 0:
                break

            next_offset = (
                partition_offsets[i + 1] if i < (len(partition_offsets) - 1) else len(data)
            )
            partition = data[offset:next_offset]

            child = await resource.create_child(
                tags=(GenericBinary,), data_range=Range(offset, next_offset)
            )
            if OPENWRT_TRX_MARK in partition:
                partition = partition[: partition.index(OPENWRT_TRX_MARK)]
                await child.create_child(
                    tags=(GenericBinary,), data_range=Range.from_size(0, len(partition))
                )


#####################
#     ANALYZERS     #
#####################
class OpenWrtTrxHeaderAttributesAnalyzer(Analyzer[None, OpenWrtTrxHeader]):
    """
    Analyze the OpenWrtTrxHeader of a OpenWrtTrx firmware file.
    """

    targets = (OpenWrtTrxHeader,)
    outputs = (OpenWrtTrxHeader,)

    async def analyze(self, resource: Resource, config=None) -> OpenWrtTrxHeader:
        tmp = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(tmp),
            endianness=Endianness.LITTLE_ENDIAN,
            word_size=4,
        )
        deserialized = deserializer.unpack_multiple("IIIHH")
        (
            trx_magic,
            trx_length,
            trx_crc,
            trx_flags,
            trx_version,
        ) = deserialized
        assert trx_magic == OPENWRT_TRX_MAGIC_START

        if trx_version not in [OpenWrtTrxVersion.VERSION1.value, OpenWrtTrxVersion.VERSION2.value]:
            raise ValueError(f"Unknown OpenWrt TRX version: {trx_version}")

        max_num_partitions = 3 if trx_version == OpenWrtTrxVersion.VERSION1.value else 4
        trx_partition_offsets = []

        for _ in range(max_num_partitions):
            offset = deserializer.unpack_uint()

            if offset == 0:
                break

            trx_partition_offsets.append(offset)

        header = OpenWrtTrxHeader(
            trx_magic, trx_length, trx_crc, trx_flags, trx_version, trx_partition_offsets
        )

        return header


####################
#    MODIFIERS     #
####################
@dataclass
class OpenWrtTrxHeaderModifierConfig(ComponentConfig):
    """
    Modifier config for a OpenWrtTrxHeader.

    The following field is not modifiable:
    - Image Header Magic Number (a constant): `trx_magic`

    The following fields are modifiable, but will be overwritten by the packer:
    - Image Data Size: `trx_length`
    - Image CRC Checksum: `trx_crc`
    - LZMA Loader offset: `trx_loader_offset`
    - Kernel offset: `trx_kernel_offset`
    - Filesystem offset: `trx_rootfs_offset`
    - BinHeader offset, applicable for TRX Version 2: `trx_binheader_offset`
    """

    trx_length: Optional[int] = None
    trx_crc: Optional[int] = None
    trx_flags: Optional[int] = None
    trx_version: Optional[int] = None
    trx_partition_offsets: Optional[List[int]] = None


class OpenWrtTrxHeaderModifier(Modifier[OpenWrtTrxHeaderModifierConfig]):
    """
    Modify a OpenWrtTrxHeader according to a given modifier config.
    """

    targets = (OpenWrtTrxHeader,)

    async def modify(self, resource: Resource, config: OpenWrtTrxHeaderModifierConfig) -> None:
        original_attributes = await resource.analyze(AttributesType[OpenWrtTrxHeader])
        new_attributes = ResourceAttributes.replace_updated(original_attributes, config)
        serialized_header = await OpenWrtTrxHeaderModifier.serialize(new_attributes)
        header_v = await resource.view_as(OpenWrtTrxHeader)
        resource.queue_patch(
            Range.from_size(0, header_v.get_header_length()),
            serialized_header,
        )
        resource.add_attributes(new_attributes)

    @staticmethod
    async def serialize(
        updated_attributes: AttributesType[OpenWrtTrxHeader],
    ) -> bytes:
        """
        Serialize `updated_attributes` into bytes. This method doesn't perform any check or compute
        any CRC.
        """
        output = struct.pack(
            "<IIIHH",
            OPENWRT_TRX_MAGIC_START,
            updated_attributes.trx_length,
            updated_attributes.trx_crc,
            updated_attributes.trx_flags,
            updated_attributes.trx_version,
        )
        if updated_attributes.trx_version == OpenWrtTrxVersion.VERSION1.value:
            num_offsets = 3
        elif updated_attributes.trx_version == OpenWrtTrxVersion.VERSION2.value:
            num_offsets = 4
        else:
            raise ValueError()
        for offset in updated_attributes.trx_partition_offsets:
            output += struct.pack("<I", offset)
        for i in range(num_offsets - len(updated_attributes.trx_partition_offsets)):
            output += struct.pack("<I", 0)
        return output


####################
#     PACKERS      #
####################
class OpenWrtTrxPacker(Packer[None]):
    """
    Pack an OpenWrtTrx firmware file.

    It consolidates the OpenWrtTrxHeader and all partition instances into a single binary, updating
    the CRC checksum, data size, and partition offsets in the header.
    """

    id = b"OpenWrtTrxPacker"
    targets = (OpenWrtTrx,)

    async def pack(self, resource: Resource, config=None):
        openwrt_v = await resource.view_as(OpenWrtTrx)
        header = await openwrt_v.get_header()
        children_by_offset = sorted(
            [
                (await child.get_data_range_within_root(), child)
                for child in await resource.get_children()
                if not child.has_tag(OpenWrtTrxHeader)
            ],
            key=lambda x: x[0].start,
        )
        repacked_data_l = [await child.get_data() for _, child in children_by_offset]
        repacked_data_b = b"".join(repacked_data_l)
        trx_length = header.get_header_length() + len(repacked_data_b)

        offsets = [r.start for r, _ in children_by_offset]
        header_config = OpenWrtTrxHeaderModifierConfig(
            trx_length=trx_length, trx_partition_offsets=offsets
        )

        await header.resource.run(OpenWrtTrxHeaderModifier, header_config)

        header_data = await header.resource.get_data()
        data_to_crc = header_data[12:] + repacked_data_b
        header_config = OpenWrtTrxHeaderModifierConfig(
            trx_crc=openwrt_crc32(data_to_crc),
        )
        await header.resource.run(OpenWrtTrxHeaderModifier, header_config)
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(header.get_header_length(), original_size), repacked_data_b)


def openwrt_crc32(data: bytes) -> int:
    """
    Calculate CRC32 a-la OpenWrt. Original implementation:
    <https://git.archive.openwrt.org/?p=14.07/openwrt.git;a=blob;f=tools/firmware-utils/src/trx.c>

    Implements CRC-32 Ethernet which requires XOR'ing the zlib.crc32 result with 0xFFFFFFFF
    """
    return (zlib.crc32(data) & 0xFFFFFFFF) ^ 0xFFFFFFFF
