import io
import struct
import zlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ofrak.component.identifier import Identifier
from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, File
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
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
    offset[0] = lzma-loader
    offset[1] = Linux-Kernel
    offset[2] = rootfs

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
    offset[0] = lzma-loader
    offset[1] = Linux-Kernel
    offset[2] = rootfs
    offset[3] = bin-Header
    ```
    """

    trx_magic: int
    trx_length: int
    trx_crc: int
    trx_flags: int
    trx_version: int
    trx_loader_offset: int
    trx_kernel_offset: int
    trx_rootfs_offset: int
    trx_binheader_offset: Optional[int]

    def get_version(self) -> OpenWrtTrxVersion:
        return OpenWrtTrxVersion(self.trx_version)

    def get_header_length(self) -> int:
        if self.get_version() == OpenWrtTrxVersion.VERSION1:
            return OPENWRT_TRXV1_HEADER_LEN
        elif self.get_version() == OpenWrtTrxVersion.VERSION2:
            return OPENWRT_TRXV2_HEADER_LEN
        else:
            raise ValueError(f"Unknown OpenWrt TRX version: {self.trx_version}")


class OpenWrtTrxLzmaLoader(GenericBinary):
    pass


class OpenWrtTrxKernel(GenericBinary):
    pass


class OpenWrtTrxRootfs(FilesystemRoot):
    pass


class OpenWrtTrxBinheader(GenericBinary):
    pass


@dataclass
class OpenWrtTrx(GenericBinary):
    """
    OpenWrtTrx is a TRX binary update for OpenWrt firmware.

    TRX binaries are used for upgrading the firmware of devices already running OpenWrt firmware

    The OpenWrtTrx consists of 1 OpenWrtTrxHeader and 3 or 4 partition(s):
        - OpenWrtTrxLzmaLoader
        - OpenWrtTrxKernel
        - OpenWrtTrxRootfs
        - OpenWrtTrxBinheader (in TRX v2)
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
    Unpack an OpenWrtTrx firmware file into:
    - OpenWrtTrxHeader
    - OpenWrtTrxLzmaLoader
    - OpenWrtTrxKernel
    - OpenWrtTrxRootfs
    - OpenWrtTrxBinheader (if TRX v2)

    The header has a mapped data range, whereas all partitions are unmapped data.
    """

    id = b"OpenWrtTrxUnpacker"
    targets = (OpenWrtTrx,)
    children = (
        OpenWrtTrxHeader,
        OpenWrtTrxLzmaLoader,
        OpenWrtTrxKernel,
        OpenWrtTrxRootfs,
        OpenWrtTrxBinheader,
    )

    async def unpack(self, resource: Resource, config=None):
        data = await resource.get_data()
        # Peek into TRX version to know how big the header is
        trx_version = OpenWrtTrxVersion(struct.unpack("<H", data[14:16])[0])
        if trx_version == OpenWrtTrxVersion.VERSION1:
            trx_header_r = await resource.create_child(
                tags=(OpenWrtTrxHeader,), data_range=Range(0, OPENWRT_TRXV1_HEADER_LEN)
            )
        elif trx_version == OpenWrtTrxVersion.VERSION2:
            trx_header_r = await resource.create_child(
                tags=(OpenWrtTrxHeader,), data_range=Range(0, OPENWRT_TRXV2_HEADER_LEN)
            )
        else:
            raise UnpackerError(f"Unknown OpenWrt TRX version: {trx_version}")

        trx_header = await trx_header_r.view_as(OpenWrtTrxHeader)
        # Create lzma loader child
        await resource.create_child(
            tags=(OpenWrtTrxLzmaLoader,),
            data=data[trx_header.trx_loader_offset : trx_header.trx_kernel_offset],
        )
        # Create kernel child
        await resource.create_child(
            tags=(OpenWrtTrxKernel,),
            data=data[trx_header.trx_kernel_offset : trx_header.trx_rootfs_offset],
        )
        if trx_version == OpenWrtTrxVersion.VERSION1:
            # Create rootfs child
            await resource.create_child(
                tags=(OpenWrtTrxRootfs,),
                data=data[trx_header.trx_rootfs_offset :],
            )
        else:  # TRX Version 2
            # Create rootfs child
            await resource.create_child(
                tags=(OpenWrtTrxRootfs,),
                data=data[trx_header.trx_rootfs_offset : trx_header.trx_binheader_offset],
            )
            # Create binHeader child
            await resource.create_child(
                tags=(OpenWrtTrxBinheader,),
                data=data[trx_header.trx_binheader_offset :],
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

        if trx_version == OpenWrtTrxVersion.VERSION1.value:
            deserialized = deserializer.unpack_multiple("III")
            (
                trx_loader_offset,
                trx_kernel_offset,
                trx_rootfs_offset,
            ) = deserialized
            header = OpenWrtTrxHeader(
                trx_magic,
                trx_length,
                trx_crc,
                trx_flags,
                trx_version,
                trx_loader_offset,
                trx_kernel_offset,
                trx_rootfs_offset,
                None,
            )
        elif trx_version == OpenWrtTrxVersion.VERSION2.value:
            deserialized = deserializer.unpack_multiple("IIII")
            (
                trx_loader_offset,
                trx_kernel_offset,
                trx_rootfs_offset,
                trx_binheader_offset,
            ) = deserialized
            header = OpenWrtTrxHeader(
                trx_magic,
                trx_length,
                trx_crc,
                trx_flags,
                trx_version,
                trx_loader_offset,
                trx_kernel_offset,
                trx_rootfs_offset,
                trx_binheader_offset,
            )
        else:
            raise ValueError(f"Unknown OpenWrt TRX version: {trx_version}")

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
    trx_loader_offset: Optional[int] = None
    trx_kernel_offset: Optional[int] = None
    trx_rootfs_offset: Optional[int] = None
    trx_binheader_offset: Optional[int] = None


class OpenWrtTrxHeaderModifier(Modifier[OpenWrtTrxHeaderModifierConfig]):
    """
    Modify a OpenWrtTrxHeader according to a given modifier config.
    """

    targets = (OpenWrtTrxHeader,)

    async def modify(self, resource: Resource, config: OpenWrtTrxHeaderModifierConfig) -> None:
        original_attributes = await resource.analyze(OpenWrtTrxHeader.attributes_type)
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
        updated_attributes: OpenWrtTrxHeader.attributes_type,  # type: ignore
    ) -> bytes:
        """
        Serialize `updated_attributes` into bytes. This method doesn't perform any check or compute
        any CRC.
        """
        if updated_attributes.trx_version == OpenWrtTrxVersion.VERSION1.value:
            return struct.pack(
                "<IIIHHIII",
                OPENWRT_TRX_MAGIC_START,
                updated_attributes.trx_length,
                updated_attributes.trx_crc,
                updated_attributes.trx_flags,
                updated_attributes.trx_version,
                updated_attributes.trx_loader_offset,
                updated_attributes.trx_kernel_offset,
                updated_attributes.trx_rootfs_offset,
            )
        elif updated_attributes.trx_version == OpenWrtTrxVersion.VERSION2.value:
            return struct.pack(
                "<IIIHHIIII",
                OPENWRT_TRX_MAGIC_START,
                updated_attributes.trx_length,
                updated_attributes.trx_crc,
                updated_attributes.trx_flags,
                updated_attributes.trx_version,
                updated_attributes.trx_loader_offset,
                updated_attributes.trx_kernel_offset,
                updated_attributes.trx_rootfs_offset,
                updated_attributes.trx_binheader_offset,
            )
        else:
            raise ValueError(f"Unknown OpenWrt TRX version: {updated_attributes.trx_version}")


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
        lzma_loader = await resource.get_only_child_as_view(
            OpenWrtTrxLzmaLoader, ResourceFilter.with_tags(OpenWrtTrxLzmaLoader)
        )
        kernel = await resource.get_only_child_as_view(
            OpenWrtTrxKernel, ResourceFilter.with_tags(OpenWrtTrxKernel)
        )
        rootfs = await resource.get_only_child_as_view(
            OpenWrtTrxRootfs, ResourceFilter.with_tags(OpenWrtTrxRootfs)
        )
        if header.get_version() == OpenWrtTrxVersion.VERSION2:
            binheader = await resource.get_only_child_as_view(
                OpenWrtTrxBinheader, ResourceFilter.with_tags(OpenWrtTrxBinheader)
            )

        repacked_data_l = []
        trx_loader_offset = header.get_header_length()
        repacked_data_l.append(await lzma_loader.resource.get_data())

        trx_kernel_offset = trx_loader_offset + len(repacked_data_l[-1])
        repacked_data_l.append(await kernel.resource.get_data())

        trx_rootfs_offset = trx_kernel_offset + len(repacked_data_l[-1])
        repacked_data_l.append(await rootfs.resource.get_data())

        if header.get_version() == OpenWrtTrxVersion.VERSION2:
            trx_binheader_offset = trx_rootfs_offset + len(repacked_data_l[-1])
            repacked_data_l.append(await binheader.resource.get_data())

        repacked_data_b = b"".join(repacked_data_l)
        trx_length = header.get_header_length() + len(repacked_data_b)

        data_to_crc = struct.pack("<H", header.trx_flags)
        data_to_crc += struct.pack("<H", header.trx_version)
        data_to_crc += struct.pack("<I", trx_loader_offset)
        data_to_crc += struct.pack("<I", trx_kernel_offset)
        data_to_crc += struct.pack("<I", trx_rootfs_offset)
        if header.get_version() == OpenWrtTrxVersion.VERSION2:
            data_to_crc += struct.pack("<I", trx_binheader_offset)
        data_to_crc += repacked_data_b

        if header.get_version() == OpenWrtTrxVersion.VERSION1:
            header_config = OpenWrtTrxHeaderModifierConfig(
                trx_length=trx_length,
                trx_crc=openwrt_crc32(data_to_crc),
                trx_loader_offset=trx_loader_offset,
                trx_kernel_offset=trx_kernel_offset,
                trx_rootfs_offset=trx_rootfs_offset,
            )
        else:
            header_config = OpenWrtTrxHeaderModifierConfig(
                trx_length=trx_length,
                trx_crc=openwrt_crc32(data_to_crc),
                trx_loader_offset=trx_loader_offset,
                trx_kernel_offset=trx_kernel_offset,
                trx_rootfs_offset=trx_rootfs_offset,
                trx_binheader_offset=trx_binheader_offset,
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
