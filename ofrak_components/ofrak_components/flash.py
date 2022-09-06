import io
from dataclasses import dataclass
from typing import Iterable, Dict
from hashlib import md5

from ofrak import Analyzer, Identifier, Packer, Resource, ResourceFilter, Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentConfig
from ofrak_type.range import Range
from ofrak.component.unpacker import UnpackerError
from ofrak_type.error import NotFoundError
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

# Dict of data MD5 checksum to ECC bytes, used to check for updates
DATA_HASHES: Dict[bytes, bytes] = dict()


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


@dataclass
class FlashLogicalDataResourceConfig(ComponentConfig):
    offset: int
    bytes: bytes
    is_insert: bool

    async def __init__(self, is_insert=False):
        self.is_insert = is_insert


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
        GenericBinary,
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
                break

        if ecc_region == None:
            raise UnpackerError("Error creating ECC resource")
        ecc_data = await ecc_region.get_data()
        ecc_data_len = len(ecc_data)

        vaddr_offset = 0
        only_data = b""
        num_possible_ecc_blocks = ecc_data_len // FLASH_BLOCK_SIZE

        # Loop through all blocks, adding child resource for each
        for block_count in range(0, num_possible_ecc_blocks):
            cur_block_offset = FLASH_BLOCK_SIZE * block_count
            cur_block_end_offset = cur_block_offset + FLASH_BLOCK_SIZE
            cur_block_data = ecc_data[cur_block_offset:cur_block_end_offset]
            cur_block_ecc = cur_block_data[cur_block_end_offset - ECC_SIZE :]
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
                    block_data_only = cur_block_data[
                        SX_ECC_MAGIC_LEN : ECC_HEADER_BLOCK_DATA_SIZE + SX_ECC_MAGIC_LEN
                    ]
                    vaddr_offset += ECC_HEADER_BLOCK_DATA_SIZE
                else:
                    # Regular data block
                    await ecc_region.create_child(
                        tags=(FlashEccBlock,),
                        data_range=Range(cur_block_offset, cur_block_end_offset),
                    )
                    block_data_only = cur_block_data[:ECC_BLOCK_DATA_SIZE]
                    vaddr_offset += ECC_BLOCK_DATA_SIZE

                only_data += block_data_only
                # Include delimiter in the ECC and MD5 calculation
                data_delim = block_data_only + cur_block_delimiter
                # Add to Dict to avoid recalculating in the future
                DATA_HASHES[md5(data_delim).digest()] = cur_block_ecc
            else:
                raise UnpackerError("Bad Flash ECC Delimiter")

        # Add tail block
        await ecc_region.create_child(
            tags=(FlashEccTailBlock,),
            data_range=Range(ecc_data_len - ECC_TAIL_BLOCK_SIZE, ecc_data_len),
        )

        # Add all block data to logical resource for recursive unpacking
        await ecc_region.create_child(
            tags=(FlashLogicalDataResource,),
            data=only_data[:vaddr_offset],
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
        # We actually want to delete ourselves and overwrite with just the repacked version
        try:
            packed_child = await resource.get_only_child(
                r_filter=ResourceFilter.with_tags(
                    FlashEccResource,
                ),
            )
            patch_data = await packed_child.get_data()
            patch_size = await packed_child.get_data_length()
        except NotFoundError:
            # Child has not been packed, return itself
            # TODO: Verify that no modifications took place without repacking child
            patch_data = await resource.get_data()
            patch_size = await resource.get_data_length()

        resource.queue_patch(Range(0, patch_size), patch_data)


class FlashLogicalDataResourcePacker(Packer[FlashConfig]):
    id = b"FlashLogicalDataResourcePacker"
    targets = (FlashLogicalDataResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        data = await resource.get_data()
        initialize_ecc()

        bytes_left = len(data)
        original_size = bytes_left
        packed_data = bytearray()
        data_offset = 0
        while bytes_left > 0:
            # Create header block
            if bytes_left == original_size:
                block_data = data[:ECC_HEADER_BLOCK_DATA_SIZE] + ECC_DATA_DELIMITER
                data_hash = md5(block_data).digest()
                if data_hash in DATA_HASHES:
                    # Data was not changed, no need to compute new ECC
                    ecc = DATA_HASHES[data_hash]
                else:
                    ecc = encode_ecc(block_data, ECC_SIZE)
                block = SX_ECC_MAGIC + block_data + ecc
                data_offset += ECC_HEADER_BLOCK_DATA_SIZE
                bytes_left -= ECC_HEADER_BLOCK_DATA_SIZE
            else:
                # Check if last block
                if bytes_left <= ECC_BLOCK_DATA_SIZE:
                    # Add padding to last block
                    block_data = bytearray(ECC_BLOCK_DATA_SIZE)
                    block_data[:bytes_left] = data[data_offset:]
                    block_data[bytes_left : bytes_left + 1] = ECC_LAST_DATA_BLOCK_DELIMITER
                else:
                    block_data = data[data_offset : data_offset + ECC_BLOCK_DATA_SIZE]
                    block_data += ECC_DATA_DELIMITER

                # Check if this block was modified by checking MD5 checksum from unpacking
                data_hash = md5(block_data).digest()
                if data_hash in DATA_HASHES:
                    ecc = DATA_HASHES[data_hash]
                else:
                    ecc = encode_ecc(block_data, ECC_SIZE)
                block = block_data + ecc
                data_offset += ECC_BLOCK_DATA_SIZE
                bytes_left -= ECC_BLOCK_DATA_SIZE
            packed_data += block

        # Add tail
        tail_block = (
            ECC_TAIL_BLOCK_DELIMITER + original_size.to_bytes(4, "big") + md5(data).digest()
        )
        ecc = encode_ecc(tail_block, ECC_TAIL_BLOCK_SIZE - ECC_SIZE)
        packed_data += tail_block + ecc
        parent = await resource.get_parent()
        await parent.create_child(tags=(FlashEccResource,), data=packed_data)


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
