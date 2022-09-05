import io
from dataclasses import dataclass
from typing import Iterable

from ofrak import Analyzer, Identifier, Packer, Resource, ResourceFilter, Unpacker
from ofrak.model.component_model import ComponentConfig
from ofrak_type.range import Range
from ofrak.component.unpacker import UnpackerError
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_type.endianness import Endianness
from ofrak.core import (
    GenericBinary,
)

from ofrak_components.ecc import initialize_ecc, encode_ecc

SX_ECC_MAGIC = b"SXECCv1"
SX_ECC_MAGIC_LEN = len(SX_ECC_MAGIC)
FLASH_BLOCK_SIZE = 255
ECC_SIZE = 32
ECC_MD5_LEN = 16
ECC_DATA_DELIMITER = b"*"
ECC_LAST_DATA_BLOCK_DELIMITER = b"$"
ECC_TAIL_BLOCK_DELIMITER = b"!"
ECC_HEADER_BLOCK_DATA_SIZE = 215
ECC_HEADER_DELIMITER_OFFSET = SX_ECC_MAGIC_LEN + ECC_HEADER_BLOCK_DATA_SIZE
ECC_BLOCK_DATA_SIZE = 222
ECC_TAIL_BLOCK_SIZE = 1 + 4 + ECC_MD5_LEN + ECC_SIZE


#####################
#     RESOURCES     #
#####################
@dataclass
class FlashEccHeaderBlock(GenericBinary):
    """
    FlashBlock makes up a small portion of the flash.
    Inside of a flash block is either just data or data + ECC.
    """

    magic: bytes
    data: bytes
    delimiter: bytes
    ecc: bytes

    def get_magic(self) -> bytes:
        return self.magic

    def get_block_data(self) -> bytes:
        return self.data

    def get_delimiter(self) -> bytes:
        return self.delimiter

    def get_ecc(self) -> bytes:
        return self.ecc


@dataclass
class FlashEccBlock(GenericBinary):
    """
    FlashBlock makes up a small portion of the flash.
    Inside of a flash block is either just data or data + ECC.
    """

    data: bytes
    delimiter: bytes
    ecc: bytes

    def get_block_data(self) -> bytes:
        return self.data

    def get_delimiter(self) -> bytes:
        return self.delimiter

    def get_ecc(self) -> bytes:
        return self.ecc


@dataclass
class FlashEccTailBlock(GenericBinary):
    """
    The final block in the ECC marked region
    """

    delimiter: bytes
    ecc_size: int  # The size of the ECC protected region
    md5: bytes
    ecc: bytes

    def get_delimiter(self) -> bytes:
        return self.delimiter

    def get_ecc_size(self) -> int:
        return self.ecc_size

    def get_md5(self) -> bytes:
        return self.md5

    def get_ecc(self) -> bytes:
        return self.ecc


@dataclass
class FlashEccResource(GenericBinary):
    """
    Overarching resource for physical representation containing FlashEccBlock
    """

    async def get_header_block_as_view(self) -> FlashEccHeaderBlock:
        return await self.resource.get_only_child_as_view(
            v_type=FlashEccHeaderBlock,
            r_filter=ResourceFilter.with_tags(
                FlashEccHeaderBlock,
            ),
        )

    async def get_blocks_as_view(self) -> Iterable[FlashEccBlock]:
        return await self.resource.get_children_as_view(
            v_type=FlashEccBlock,
            r_filter=ResourceFilter.with_tags(
                FlashEccBlock,
            ),
        )

    async def get_tail_block_as_view(self) -> FlashEccTailBlock:
        return await self.resource.get_only_child_as_view(
            v_type=FlashEccTailBlock,
            r_filter=ResourceFilter.with_tags(
                FlashEccTailBlock,
            ),
        )

    async def get_flash_data(self) -> bytes:
        data = b""

        # Header includes data
        header_block_view = await self.get_header_block_as_view()
        data += header_block_view.get_block_data()

        # Get the regular data blocks but sort by their index within parent
        ecc_blocks = await self.get_blocks_as_view()
        ecc_blocks_sorted = [
            (await b.resource.get_data_index_within_parent(), b) for b in ecc_blocks
        ]
        ecc_blocks_sorted.sort()
        sorted_blocks = [x for key, x in ecc_blocks_sorted]

        for block in sorted_blocks:
            data += block.data

        tail_block_view = await self.get_tail_block_as_view()
        expected_size = tail_block_view.get_ecc_size()
        return data[:expected_size]

    async def get_flash_ecc(self) -> bytes:
        ecc = b""
        header_block_view = await self.get_header_block_as_view()
        ecc += header_block_view.get_ecc()

        ecc_blocks = await self.get_blocks_as_view()
        ecc_blocks_sorted = [
            (await b.resource.get_data_index_within_parent(), b) for b in ecc_blocks
        ]
        ecc_blocks_sorted.sort()
        sorted_blocks = [x for key, x in ecc_blocks_sorted]

        for block in sorted_blocks:
            ecc += block.get_ecc()

        return ecc


@dataclass
class FlashLogicalDataResource(GenericBinary):
    """
    This is the final product of unpacking a FlashResource.
    It contains the data without any ECC or OOB data included.
    This allows for recursive packing and unpacking.
    """


@dataclass
class FlashEccProtectedResource(GenericBinary):
    """
    Region of memory protected by ECC
    """


@dataclass
class FlashResource(GenericBinary):
    """
    The overarching resource that encapsulates flash storage.
    This is made up of several blocks.
    """


#####################
#      CONFIGS      #
#####################
@dataclass
class FlashConfig(ComponentConfig):
    pass


#####################
#    IDENTIFIER     #
#####################
class FlashEccIdentifier(Identifier[None]):
    """
    Identify an ECC protected region by searching for the magic bytes
    """

    targets = (FlashResource,)

    async def identify(self, resource: Resource, config=None):
        data = await resource.get_data()
        if SX_ECC_MAGIC in data:
            resource.add_tag(FlashEccProtectedResource)


#####################
#     ANALYZERS     #
#####################
class FlashEccHeaderBlockAnalyzer(Analyzer[None, FlashConfig]):
    targets = (FlashEccHeaderBlock,)
    outputs = (FlashEccHeaderBlock,)

    async def analyze(self, resource: Resource, config=None) -> FlashEccHeaderBlock:
        resource_data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(resource_data),
            endianness=Endianness.BIG_ENDIAN,
            word_size=2,
        )

        deserialized = deserializer.unpack_multiple(
            f"{SX_ECC_MAGIC_LEN}s{ECC_HEADER_BLOCK_DATA_SIZE}sB{ECC_SIZE}s"
        )
        (
            f_magic,
            f_data,
            f_delimiter,
            f_ecc,
        ) = deserialized

        assert f_magic == SX_ECC_MAGIC

        return FlashEccHeaderBlock(
            f_magic,
            f_data,
            f_delimiter,
            f_ecc,
        )


class FlashEccBlockAnalyzer(Analyzer[None, FlashConfig]):
    targets = (FlashEccBlock,)
    outputs = (FlashEccBlock,)

    async def analyze(self, resource: Resource, config=None) -> FlashEccBlock:
        resource_data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(resource_data),
            endianness=Endianness.BIG_ENDIAN,
            word_size=2,
        )

        deserialized = deserializer.unpack_multiple(f"{ECC_BLOCK_DATA_SIZE}sB{ECC_SIZE}s")
        (
            block_data,
            block_delimiter,
            block_ecc,
        ) = deserialized

        return FlashEccBlock(
            block_data,
            block_delimiter,
            block_ecc,
        )


class FlashEccTailBlockAnalyzer(Analyzer[None, FlashConfig]):
    targets = (FlashEccTailBlock,)
    outputs = (FlashEccTailBlock,)

    async def analyze(self, resource: Resource, config=None) -> FlashEccTailBlock:
        resource_data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(resource_data),
            endianness=Endianness.BIG_ENDIAN,
            word_size=2,
        )

        deserialized = deserializer.unpack_multiple(f"BI{ECC_MD5_LEN}s{ECC_SIZE}s")
        (
            f_delimiter,
            f_ecc_size,
            f_md5,
            f_ecc,
        ) = deserialized

        return FlashEccTailBlock(
            f_delimiter,
            f_ecc_size,
            f_md5,
            f_ecc,
        )


#####################
#     UNPACKERS     #
#####################
class FlashEccProtectedResourceUnpacker(Unpacker[None]):
    """
    Unpack regions of flash protected by ECC
    """

    targets = (FlashEccProtectedResource,)
    children = (
        FlashEccResource,
        FlashEccHeaderBlock,
        FlashEccBlock,
        FlashEccTailBlock,
        FlashLogicalDataResource,
    )

    async def unpack(self, resource: Resource, config=None):
        data = await resource.get_data()
        data_len = len(data)
        ecc_magic_offset = data.find(SX_ECC_MAGIC)

        initialize_ecc()

        # Get the end of the ecc_region
        # Find the tail delimiter followed by the number of data bytes up to that point
        search_index = ecc_magic_offset
        while search_index < data_len:
            delimiter_index = data.find(ECC_TAIL_BLOCK_DELIMITER, search_index, data_len)
            # Catch delimiter before it tries to loop back to first search hit
            if delimiter_index == -1:
                raise UnpackerError("Unable to find end of ECC protected region")
            search_index = delimiter_index + 1
            relative_offset = delimiter_index - ecc_magic_offset
            read_size = int.from_bytes(data[delimiter_index + 1 : delimiter_index + 5], "big")
            expected_data_bytes = _flash_p2l(relative_offset)

            # Check that the size read is within a block size of expected, in case of padding
            if 0 <= (expected_data_bytes - read_size) <= ECC_BLOCK_DATA_SIZE:
                # Add overarching flash region resource
                ecc_region = await resource.create_child(
                    tags=(FlashEccResource,),
                    data_range=Range(ecc_magic_offset, delimiter_index + ECC_TAIL_BLOCK_SIZE),
                )

                # Add tail block while we're here
                await ecc_region.create_child(
                    tags=(FlashEccTailBlock,),
                    data_range=Range(relative_offset, relative_offset + ECC_TAIL_BLOCK_SIZE),
                )
                break

        if ecc_region == None:
            raise UnpackerError("Error creating ECC resource")
        ecc_data = await ecc_region.get_data()
        ecc_data_len = len(ecc_data)
        ecc_data_size = 0
        only_data = b""
        num_possible_ecc_blocks = ecc_data_len // FLASH_BLOCK_SIZE

        # Loop through all blocks, adding child resource for each
        for block_count in range(0, num_possible_ecc_blocks):
            cur_block_offset = FLASH_BLOCK_SIZE * block_count
            cur_block_end_offset = cur_block_offset + FLASH_BLOCK_SIZE
            cur_block_data = ecc_data[cur_block_offset:cur_block_end_offset]
            cur_block_delimiter = cur_block_data[ECC_BLOCK_DATA_SIZE : ECC_BLOCK_DATA_SIZE + 1]
            if (
                cur_block_delimiter == ECC_DATA_DELIMITER
                or cur_block_delimiter == ECC_LAST_DATA_BLOCK_DELIMITER
            ):
                if block_count == 0:
                    # Verify ECC header block to confirm there is a protected region
                    if (
                        ecc_data[cur_block_offset : cur_block_offset + SX_ECC_MAGIC_LEN]
                        != SX_ECC_MAGIC
                    ):
                        raise UnpackerError("Bad ECC Magic")

                    await ecc_region.create_child(
                        tags=(FlashEccHeaderBlock,),
                        data_range=Range(cur_block_offset, cur_block_end_offset),
                    )
                    only_data += cur_block_data[: ECC_HEADER_BLOCK_DATA_SIZE + 1]
                    ecc_data_size += ECC_HEADER_BLOCK_DATA_SIZE
                else:
                    # Regular data block
                    await ecc_region.create_child(
                        tags=(FlashEccBlock,),
                        data_range=Range(cur_block_offset, cur_block_end_offset),
                    )
                    ecc = encode_ecc(
                        cur_block_data[: ECC_BLOCK_DATA_SIZE + 1], ECC_BLOCK_DATA_SIZE + 1
                    )
                    print(ecc.hex())
                    only_data += cur_block_data[: ECC_BLOCK_DATA_SIZE + 1]
                    ecc_data_size += ECC_BLOCK_DATA_SIZE
            else:
                raise UnpackerError("Bad Flash ECC Delimiter")

        # Add all block data to logical resource for recursive unpacking
        await ecc_region.create_child(
            tags=(FlashLogicalDataResource, GenericBinary),
            data=only_data[:read_size],
        )


#####################
#      PACKERS      #
#####################
class FlashResourcePacker(Packer[FlashConfig]):
    """
    Packs the FlashResource into binary and cleans up logical data representations
    """

    id = b"FlashResourcePacker"
    targets = (FlashResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        # Cleanup logical resources
        logical_resources = await resource.get_descendants(
            r_filter=ResourceFilter.with_tags(
                FlashLogicalDataResource,
            ),
        )
        for res in logical_resources:
            await res.delete()

        # We treat the data as raw bytes without any further processing
        original_data = await resource.get_data()
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), original_data)


class FlashEccResourcePacker(Packer[FlashConfig]):
    """
    Packs the ECC protected region back into a binary blob
    """

    id = b"FlashEccResourcePacker"
    targets = (FlashEccResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        data = b""
        ecc_view = await resource.view_as(FlashEccResource)
        header_view = await ecc_view.get_header_block_as_view()
        data += header_view.resource.get_data()
        blocks = await ecc_view.get_blocks_as_view()
        for block in blocks:
            data += block.resource.get_data()
        tail_view = await ecc_view.get_tail_block_as_view()
        data += tail_view.resource.get_data()

        # Patch original data
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), data)


#####################
#      HELPERS      #
#####################
def _get_physical_block_index(l_offset: int) -> int:
    """
    Returns the index of the physical block corresponding to a logical address
    """
    if l_offset <= ECC_HEADER_BLOCK_DATA_SIZE:
        return 0
    return ((l_offset - ECC_HEADER_BLOCK_DATA_SIZE) // ECC_BLOCK_DATA_SIZE) + 1


def _flash_l2p(l_offset: int) -> int:
    """
    Returns the physical address given a logical address of contiguous memory
    """
    if l_offset <= ECC_HEADER_BLOCK_DATA_SIZE:
        return l_offset
    return (
        ((l_offset // ECC_BLOCK_DATA_SIZE) * FLASH_BLOCK_SIZE)
        + (l_offset % ECC_BLOCK_DATA_SIZE)
        + SX_ECC_MAGIC_LEN
    )


def _flash_p2l(p_offset: int) -> int:
    """
    Returns the logical address given a valid physical data address
    If a physical memory address does not have data then it will return an unexpected value
    """
    # TODO: Handle input that is not in a data section
    if p_offset <= ECC_HEADER_BLOCK_DATA_SIZE:
        return p_offset
    return (
        ((p_offset // FLASH_BLOCK_SIZE) * ECC_BLOCK_DATA_SIZE) + (p_offset % FLASH_BLOCK_SIZE) - 7
    )
