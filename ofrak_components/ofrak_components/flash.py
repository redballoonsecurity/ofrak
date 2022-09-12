import io
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Iterable, Optional

from ofrak import (
    Analyzer,
    Identifier,
    Packer,
    Resource,
    ResourceFilter,
    Unpacker,
)
from ofrak.component.identifier import IdentifierError
from ofrak.component.unpacker import UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentConfig
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_type.endianness import Endianness
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

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

    data: bytes
    ecc: bytes
    magic: Optional[bytes] = None
    delimiter: Optional[bytes] = None

    def get_block_data(self) -> bytes:
        return self.data

    def get_ecc(self) -> bytes:
        return self.ecc

    def get_magic(self) -> bytes:
        return self.magic

    def get_delimiter(self) -> bytes:
        return self.delimiter


@dataclass
class FlashEccBlock(GenericBinary):
    """
    FlashBlock makes up a small portion of the flash.
    Inside of a flash block is either just data or data + ECC.
    """

    data: bytes
    ecc: bytes
    delimiter: Optional[bytes] = None

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

    ecc_size: int  # The size of the ECC protected region
    ecc: bytes
    delimiter: Optional[bytes] = None
    md5: Optional[bytes] = None

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
class FlashLogicalEccResource(GenericBinary):
    """
    The alternate to FlashLogicalDataResource.
    Generally less useful on its own but provided anyway.
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
class FlashEccPositionType(Enum):
    """
    Describes the position of the ECC in relation to the data
    - Separate is where all data comes before/after all of the ECC
        .------.------.------.------.
        | Data | Data |  ECC |  ECC |
        `------`------`------`------`
    - Adjacent interweaves ECC at the start/end of pages
        .------.------.------.------.
        | Data |  ECC | Data |  ECC |
        `------`------`------`------`
    """

    SEPARATE_ECC_PRE = 0
    SEPARATE_ECC_POST = 1
    ADJACENT_ECC_PRE = 2
    ADJACENT_ECC_POST = 3


class FlashBlockFieldPositionType(Enum):
    """
    Specifies where a field is relative to the start of the block
    """

    START_OF_BLOCK = 0
    AFTER_DATA = 1
    END_OF_BLOCK = 2


@dataclass
class FlashEccConfig(ComponentConfig):
    """
    Must be configured if the Flash has ECC protection
    """

    ecc_size: int
    ecc_position: FlashEccPositionType
    ecc_class: Callable[[Any], Any]
    ecc_magic: Optional[bytes] = None
    head_delimiter: Optional[bytes] = None
    first_data_delimiter: Optional[bytes] = None
    data_delimiter: Optional[bytes] = None
    last_data_delimiter: Optional[bytes] = None
    tail_delimiter: Optional[bytes] = None
    delimiter_position: Optional[FlashBlockFieldPositionType] = None

    def get_magic_len(self) -> int:
        if self.ecc_magic is not None:
            return len(self.ecc_magic)
        return None


class FlashFieldType(Enum):
    DATA = 0
    ECC = 1
    MAGIC = 2
    DATA_SIZE = 3
    ECC_SIZE = 4
    CHECKSUM = 5
    DELIMITER = 6


class FlashFieldPositionType(Enum):
    """
    Describes the position of a field relative to entire ECC region
    """

    HEAD_POSITION = 0
    TAIL_POSITION = 1
    HEAD_TAIL_POSITION = 2


@dataclass
class FlashConfig(ComponentConfig):
    """
    FlashConfig is for specifying everything about the specific model of flash
    The intent is to expand to all common flash configurations.
    """

    block_size: int
    ecc_config: Optional[FlashEccConfig] = None
    checksum_func: Optional[Callable[[Any], Any]] = None
    checksum_position: Optional[FlashFieldPositionType] = None
    checksum_len: Optional[int] = None
    data_count_size: Optional[int] = None
    data_count_position: Optional[FlashFieldPositionType] = None

    def get_block_data_size(self, magic_len=None, delim_len=None, ecc_size=None):
        return -sum(
            filter(
                None,
                [
                    -self.block_size,
                    magic_len,
                    delim_len,
                    ecc_size,
                ],
            )
        )

    def get_header_block_data_size(self) -> int:
        return self.get_block_data_size(
            magic_len=self.ecc_config.get_magic_len(),
            delim_len=len(self.ecc_config.head_delimiter),
            ecc_size=self.ecc_config.ecc_size,
        )

    def get_data_block_data_size(self) -> int:
        return self.get_block_data_size(
            delim_len=len(self.ecc_config.data_delimiter),
            ecc_size=self.ecc_config.ecc_size,
        )

    def get_last_data_block_data_size(self) -> int:
        return self.get_block_data_size(
            delim_len=len(self.ecc_config.last_data_delimiter),
            ecc_size=self.ecc_config.ecc_size,
        )

    def get_tail_size(self) -> int:
        return sum(
            filter(
                None,
                [
                    len(self.ecc_config.tail_delimiter),
                    self.data_count_size,
                    self.checksum_len,
                    self.ecc_config.ecc_size,
                ],
            )
        )


#####################
#    IDENTIFIER     #
#####################
class FlashEccIdentifier(Identifier[FlashConfig]):
    """
    Identify an ECC protected region by searching for the magic bytes
    """

    targets = (FlashResource,)

    async def identify(self, resource: Resource, config=FlashConfig):
        if config.ecc_config.ecc_magic is not None:
            data = await resource.get_data()
            if config.ecc_config.ecc_magic not in data:
                raise IdentifierError("Flash magic bytes present but not found in resource")
            resource.add_tag(FlashEccProtectedResource)


#####################
#     ANALYZERS     #
#####################
class FlashEccHeaderBlockAnalyzer(Analyzer[None, FlashConfig]):
    targets = (FlashEccHeaderBlock,)
    outputs = (FlashEccHeaderBlock,)

    async def analyze(self, resource: Resource, config=FlashConfig) -> FlashEccHeaderBlock:
        resource_data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(resource_data),
            endianness=Endianness.BIG_ENDIAN,
            word_size=2,
        )

        deserialized = deserializer.unpack_multiple(
            f"{config.ecc_config.get_magic_len()}s{config.get_header_block_data_size()}sB{config.ecc_config.ecc_size}s"
        )
        (
            f_magic,
            f_data,
            f_delimiter,
            f_ecc,
        ) = deserialized

        return FlashEccHeaderBlock(
            f_magic,
            f_data,
            f_delimiter,
            f_ecc,
        )


class FlashEccBlockAnalyzer(Analyzer[None, FlashConfig]):
    targets = (FlashEccBlock,)
    outputs = (FlashEccBlock,)

    async def analyze(self, resource: Resource, config=FlashConfig) -> FlashEccBlock:
        resource_data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(resource_data),
            endianness=Endianness.BIG_ENDIAN,
            word_size=2,
        )

        deserialized = deserializer.unpack_multiple(
            f"{config.get_data_block_data_size()}sB{config.ecc_config.ecc_size}s"
        )
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

    async def analyze(self, resource: Resource, config=FlashConfig) -> FlashEccTailBlock:
        resource_data = await resource.get_data()
        deserializer = BinaryDeserializer(
            io.BytesIO(resource_data),
            endianness=Endianness.BIG_ENDIAN,
            word_size=2,
        )

        deserialized = deserializer.unpack_multiple(
            f"BI{config.checksum_len}s{config.ecc_config.ecc_size}s"
        )
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
class FlashEccProtectedResourceUnpacker(Unpacker[FlashConfig]):
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
        FlashLogicalEccResource,
    )

    async def unpack(self, resource: Resource, config: FlashConfig = FlashConfig):
        data = await resource.get_data()
        data_len = len(data)

        ecc_config: FlashEccConfig = config.ecc_config
        if ecc_config is None:
            UnpackerError("Tried unpacking FlashEccProtectedResource without FlashEccConfig")
        magic = ecc_config.ecc_magic
        if magic is not None:
            ecc_magic_offset = data.find(magic)
            search_index = ecc_magic_offset
        else:
            search_index = 0

        if (
            config.data_count_position is FlashFieldPositionType.HEAD_POSITION
            or config.data_count_position is FlashFieldPositionType.HEAD_TAIL_POSITION
        ):
            # We already know the expected data length so add OOB data to get real offset
            pass
        # Get the end of the ecc_region
        # Find the tail delimiter followed by the number of data bytes up to that point
        while search_index < data_len:
            delimiter_index = data.find(ecc_config.tail_delimiter, search_index, data_len)
            # Catch delimiter before it tries to loop back to first search hit
            if delimiter_index == -1:
                raise UnpackerError("Unable to find end of ECC protected region")
            search_index = delimiter_index + 1
            relative_offset = delimiter_index - ecc_magic_offset
            read_size = int.from_bytes(data[delimiter_index + 1 : delimiter_index + 5], "big")
            expected_data_bytes = _flash_p2l(
                block_size=config.block_size,
                header_block_data_size=config.get_header_block_data_size(),
                ecc_block_data_size=config.get_data_block_data_size(),
                p_offset=relative_offset,
            )

            # Check that the size read is within a block size of expected, in case of padding
            if 0 <= (expected_data_bytes - read_size) <= config.get_data_block_data_size():
                # Add overarching flash region resource
                ecc_region = await resource.create_child(
                    tags=(FlashEccResource,),
                    data_range=Range(ecc_magic_offset, delimiter_index + config.get_tail_size()),
                )
                break

        if ecc_region == None:
            raise UnpackerError("Error creating ECC resource")
        ecc_data = await ecc_region.get_data()
        ecc_data_len = len(ecc_data)

        vaddr_offset = 0
        only_data = b""
        only_ecc = b""
        num_possible_ecc_blocks = ecc_data_len // config.block_size

        # Loop through all blocks, adding child resource for each
        for block_count in range(0, num_possible_ecc_blocks):
            cur_block_offset = config.block_size * block_count
            cur_block_end_offset = cur_block_offset + config.block_size
            cur_block_data = ecc_data[cur_block_offset:cur_block_end_offset]
            cur_block_ecc = cur_block_data[config.block_size - ecc_config.ecc_size :]
            cur_block_delimiter = cur_block_data[
                config.get_data_block_data_size() : config.get_data_block_data_size() + 1
            ]
            if (
                cur_block_delimiter == ecc_config.data_delimiter
                or cur_block_delimiter == ecc_config.last_data_delimiter
            ):
                if block_count == 0:
                    # Verify ECC header block to confirm there is a protected region
                    if (
                        ecc_data[cur_block_offset : cur_block_offset + ecc_config.get_magic_len()]
                        != ecc_config.ecc_magic
                    ):
                        raise UnpackerError("Bad ECC Magic")

                    await ecc_region.create_child(
                        tags=(FlashEccHeaderBlock,),
                        data_range=Range(cur_block_offset, cur_block_end_offset),
                    )
                    block_data_only = cur_block_data[
                        ecc_config.get_magic_len() : config.get_header_block_data_size()
                        + ecc_config.get_magic_len()
                    ]
                    vaddr_offset += config.get_header_block_data_size()
                else:
                    # Regular data block
                    await ecc_region.create_child(
                        tags=(FlashEccBlock,),
                        data_range=Range(cur_block_offset, cur_block_end_offset),
                    )
                    block_data_only = cur_block_data[: config.get_data_block_data_size()]
                    vaddr_offset += config.get_data_block_data_size()

                only_data += block_data_only
                only_ecc += cur_block_ecc
                # Include delimiter in the ECC and MD5 calculation
                data_delim = block_data_only + cur_block_delimiter
                # Add to Dict to avoid recalculating in the future
                DATA_HASHES[config.checksum_func(data_delim).digest()] = cur_block_ecc
            else:
                raise UnpackerError("Bad Flash ECC Delimiter")

        # Add tail block
        await ecc_region.create_child(
            tags=(FlashEccTailBlock,),
            data_range=Range(ecc_data_len - config.get_tail_size(), ecc_data_len),
        )

        # Add all block data to logical resource for recursive unpacking
        await ecc_region.create_child(
            tags=(FlashLogicalDataResource,),
            data=only_data[:vaddr_offset],
        )
        await ecc_region.create_child(
            tags=(FlashLogicalEccResource,),
            data=only_ecc,
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
        pass


class FlashEccResourcePacker(Packer[FlashConfig]):
    """
    Packs the ECC protected region back into a binary blob
    """

    id = b"FlashEccResourcePacker"
    targets = (FlashEccResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        # We actually want to overwrite ourselves with just the repacked version
        try:
            packed_child = await resource.get_only_child(
                r_filter=ResourceFilter.with_tags(
                    FlashEccResource,
                ),
            )
            patch_data = await packed_child.get_data()
        except NotFoundError:
            # Child has not been packed, return itself
            patch_data = await resource.get_data()
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), patch_data)


class FlashLogicalDataResourcePacker(Packer[FlashConfig]):
    id = b"FlashLogicalDataResourcePacker"
    targets = (FlashLogicalDataResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        # Need to check for the proper configs before continuing
        ecc_config = config.ecc_config
        if ecc_config is None:
            UnpackerError("Tried packing FlashLogicalDataResource without FlashEccConfig")
        ecc_class = ecc_config.ecc_class
        if ecc_class is None:
            UnpackerError("Cannot pack FlashLogicalDataResource without providing ECC class")

        data = await resource.get_data()
        bytes_left = len(data)
        original_size = bytes_left
        packed_data = bytearray()
        data_offset = 0
        while bytes_left > 0:
            if bytes_left == original_size:
                # Create header block
                block_data = data[: config.get_header_block_data_size()] + ecc_config.data_delimiter
                if config.checksum_func is not None:
                    data_hash = config.checksum_func(block_data).digest()
                if data_hash in DATA_HASHES:
                    # Data was not changed, no need to compute new ECC
                    ecc = DATA_HASHES[data_hash]
                else:
                    # Include magic in the ECC
                    ecc = ecc_class.encode(ecc_config.ecc_magic + block_data)[
                        -ecc_config.ecc_size :
                    ]
                block = ecc_config.ecc_magic + block_data + ecc
                data_offset += config.get_header_block_data_size()
                bytes_left -= config.get_header_block_data_size()
            else:
                # Check if last block
                if bytes_left <= config.get_data_block_data_size():
                    # Add padding to last block
                    block_data = bytearray(config.get_data_block_data_size())
                    block_data[:bytes_left] = data[data_offset:]
                    block_data[config.get_data_block_data_size() :] = ecc_config.last_data_delimiter
                else:
                    block_data = data[data_offset : data_offset + config.get_data_block_data_size()]
                    block_data += ecc_config.data_delimiter

                # Check if this block was modified by checking MD5 checksum from unpacking
                data_hash = config.checksum_func(block_data).digest()
                if data_hash in DATA_HASHES:
                    ecc = DATA_HASHES[data_hash]
                else:
                    ecc = ecc_class.encode(block_data)[-ecc_config.ecc_size :]
                block = block_data + ecc
                data_offset += config.get_data_block_data_size()
                bytes_left -= config.get_data_block_data_size()
            packed_data += block

        # Add tail block
        tail_block = (
            ecc_config.tail_delimiter
            + original_size.to_bytes(4, "big")
            + config.checksum_func(data).digest()
        )
        ecc = ecc_class.encode(tail_block)[-ecc_config.ecc_size :]
        packed_data += tail_block + ecc
        # Create child under the FlashEccResource to show that it packed itself
        parent = await resource.get_parent()
        await parent.create_child(tags=(FlashEccResource,), data=packed_data)


#####################
#      HELPERS      #
#####################
def _get_physical_block_index(
    header_block_data_size: int, ecc_block_data_size: int, l_offset: int
) -> int:
    """
    Returns the index of the physical block corresponding to a logical address
    """
    if l_offset <= header_block_data_size:
        return 0
    return ((l_offset - header_block_data_size) // ecc_block_data_size) + 1


def _flash_l2p(
    block_size: int,
    header_block_data_size: int,
    ecc_block_data_size: int,
    magic_len: int,
    l_offset: int,
) -> int:
    """
    Returns the physical address given a logical address of contiguous memory
    """
    if l_offset <= header_block_data_size:
        return l_offset
    return (
        ((l_offset // ecc_block_data_size) * block_size)
        + (l_offset % ecc_block_data_size)
        + magic_len
    )


def _flash_p2l(
    block_size: int, header_block_data_size: int, ecc_block_data_size: int, p_offset: int
) -> int:
    """
    Returns the logical address given a valid physical data address
    If a physical memory address does not have data then it will return an unexpected value
    """
    # TODO: Handle input that is not in a data section
    if p_offset <= header_block_data_size:
        return p_offset
    return ((p_offset // block_size) * ecc_block_data_size) + (p_offset % block_size) - 7
