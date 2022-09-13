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
    data_size: Optional[int] = None
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
        return 0


class FlashFieldType(Enum):
    DATA = 0
    ECC = 1
    MAGIC = 2
    DATA_SIZE = 3
    ECC_SIZE = 4
    CHECKSUM = 5
    DELIMITER = 6


# class FlashFieldPositionType(Enum):
#     """
#     Describes the position of a field relative to entire ECC region
#     """

#     HEAD_POSITION = 0
#     TAIL_POSITION = 1
#     HEAD_TAIL_POSITION = 2


@dataclass
class FlashField:
    field_type: FlashFieldType
    size: int


@dataclass
class FlashConfig(ComponentConfig):
    """
    FlashConfig is for specifying everything about the specific model of flash
    The intent is to expand to all common flash configurations.
    Every block has a format specifier to show where each field is in the block as well as the length
    If there is no ECC, data_block_format may take this form:
        data_block_format = [FlashField(field_type=FlashFieldType.DATA,size=block_size),],

    Note:
    Only define first_data_block_format and last_data_block_format if they are different from data_block_format
    """

    block_size: int
    data_block_format: Iterable[FlashField]
    header_block_format: Optional[Iterable[FlashField]] = None
    first_data_block_format: Optional[Iterable[FlashField]] = None
    last_data_block_format: Optional[Iterable[FlashField]] = None
    tail_block_format: Optional[Iterable[FlashField]] = None
    ecc_config: Optional[FlashEccConfig] = None
    checksum_func: Optional[Callable[[Any], Any]] = None
    # checksum_position: Optional[FlashFieldPositionType] = None
    # data_count_size: Optional[int] = None
    # data_count_position: Optional[FlashFieldPositionType] = None

    def get_block_size(self, block_format: Iterable[FlashField]) -> int:
        if block_format is not None:
            size = 0
            for field in block_format:
                size += field.size
            return size
        return None

    def get_oob_size_in_block(self, block_format: Iterable[FlashField]) -> int:
        data_range = self.get_data_range_in_block(block_format=block_format)
        if data_range is not None:
            data_length = data_range.length()
            return self.get_block_size(block_format=block_format) - data_length
        return None

    def get_field_in_block(
        self, block_format: Iterable[FlashField], field_type: FlashFieldType
    ) -> FlashField:
        for field in block_format:
            if field.field_type is field_type:
                return field
        return None

    def get_field_range_in_block(
        self, block_format: Iterable[FlashField], field_type: FlashFieldType
    ) -> Range:
        offset = 0
        for field in block_format:
            if field.field_type is field_type:
                data_size = field.size
                return Range(offset, offset + data_size)
            # Add all data in fields that come before data
            offset += field.size
        return None

    def get_field_data_in_block(
        self,
        block_format: Iterable[FlashField],
        field_type: FlashFieldType,
        data: bytes,
        block_start_offset: int,
    ) -> bytes:
        field_range = self.get_field_range_in_block(
            block_format=block_format, field_type=field_type
        )
        return data[block_start_offset + field_range.start : block_start_offset + field_range.end]

    def get_data_range_in_block(self, block_format: Iterable[FlashField]) -> Range:
        return self.get_field_range_in_block(
            block_format=block_format, field_type=FlashFieldType.DATA
        )

    def get_ecc_range_in_block(self, block_format: Iterable[FlashField]) -> Range:
        return self.get_field_range_in_block(
            block_format=block_format, field_type=FlashFieldType.ECC
        )

    def flash_p2l(self, p_offset: int) -> int:
        """
        Returns the logical address given a valid physical data address
        If a physical memory address does not have data then it will return an unexpected value
        """
        # TODO: Handle input that is not in a data section
        # TODO: More testing of edge cases
        header_block_size = self.get_block_size(self.header_block_format)
        if header_block_size is not None:
            if p_offset <= header_block_size:
                return p_offset
        return (
            ((p_offset // self.block_size) * self.get_block_size(self.data_block_format))
            + (p_offset % self.block_size)
            - self.ecc_config.get_magic_len()  # TODO: Fix extra OOB adjustment
        )

    def flash_l2p(
        self,
        l_offset: int,
    ) -> int:
        """
        Returns the physical address given a logical address of contiguous memory
        """
        header_block_size = self.get_block_size(self.header_block_format)
        if header_block_size is not None:
            if l_offset <= header_block_size:
                return l_offset
        data_block_size = self.get_block_size(self.data_block_format)

        return (
            ((l_offset // data_block_size) * self.block_size)
            + (l_offset % data_block_size)
            + 7  # TODO: Fix extra OOB adjustment
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
        ecc_config: FlashEccConfig = config.ecc_config
        if ecc_config is None:
            UnpackerError("Tried unpacking FlashEccProtectedResource without FlashEccConfig")

        data = await resource.get_data()
        data_len = len(data)
        magic = ecc_config.ecc_magic
        if magic is not None:
            ecc_magic_offset = data.find(magic)
            start_index = ecc_magic_offset
        else:
            start_index = 0

        data_size_in_header = config.get_field_in_block(
            config.header_block_format, FlashFieldType.DATA_SIZE
        )
        if config.header_block_format is not None and data_size_in_header is not None:
            # Found data_size field in the header block, just need to calculate expected total size (including OOB)
            # TODO: Craft test flash dump and verify
            expected_data_size = data_size_in_header
            read_data_size = config.get_field_data_in_block(
                block_format=config.header_block_format,
                field_type=FlashFieldType.DATA_SIZE,
                data=data,
                block_start_offset=0,
            )

            oob_size = 0
            for c in [
                config.header_block_format,
                config.first_data_block_format,
                config.data_block_format,
                config.last_data_block_format,
                config.tail_block_format,
            ]:
                if c is not None:
                    block_oob_size = config.get_oob_size_in_block(c)
                    if block_oob_size is not None:
                        oob_size += block_oob_size

            total_ecc_protected_size = oob_size + int.from_bytes(read_data_size, "big")
            if total_ecc_protected_size > data_len:
                UnpackerError("Expected larger resource than supplied")

            ecc_resource = await resource.create_child(
                tags=(FlashEccResource,),
                data_range=Range(start_index, start_index + total_ecc_protected_size),
            )

        elif (
            config.tail_block_format is not None
            and config.get_field_in_block(config.tail_block_format, FlashFieldType.DELIMITER)
            is not None
        ):
            # Delimiter in the tail, also need another field to validate this is not a false positive
            magic = config.get_field_in_block(config.tail_block_format, FlashFieldType.MAGIC)
            expected_size = config.get_field_in_block(
                config.tail_block_format, FlashFieldType.DATA_SIZE
            )
            checksum = config.get_field_in_block(config.tail_block_format, FlashFieldType.CHECKSUM)
            if magic is not None:
                verifier = FlashFieldType.MAGIC
            elif expected_size is not None:
                verifier = FlashFieldType.DATA_SIZE
            elif checksum is not None:
                verifier = FlashFieldType.CHECKSUM
            else:
                # Looking for the delimiter alone would be useless since we have nothing else to confirm it is really the end
                # TODO: Add case for long delimiter, calculate the confidence level based on data_len and length of delimiter
                resource.add_tag(FlashEccResource)
                ecc_resource = resource

            if verifier is not None:
                search_index = start_index
                while search_index < data_len:
                    if ecc_config.tail_delimiter is None:
                        raise UnpackerError(
                            "Specified DELIMITER field in tail block, but supplied no tail_delimiter in FlashEccConfig"
                        )
                    delim_offset = data.find(ecc_config.tail_delimiter, search_index, data_len)
                    if delim_offset == -1:
                        # Catch delimiter before it tries to loop back to first search hit
                        raise UnpackerError("Unable to find end of ECC protected region")
                    search_index = delim_offset + 1

                    # Need to know where delimiter is within the current block
                    delim_offset_in_block = config.get_field_range_in_block(
                        config.tail_block_format, FlashFieldType.DELIMITER
                    )
                    block_start_offset = delim_offset - delim_offset_in_block.start
                    tail_block_size = config.get_block_size(config.tail_block_format)
                    block_end_offset = block_start_offset + tail_block_size

                    read_size_bytes = config.get_field_data_in_block(
                        block_format=config.tail_block_format,
                        field_type=verifier,
                        data=data,
                        block_start_offset=block_start_offset,
                    )
                    read_size = int.from_bytes(read_size_bytes, "big")
                    relative_offset = delim_offset - start_index
                    # Subtract OOB data from relative offset to get just data size
                    expected_data_size = config.flash_p2l(p_offset=relative_offset)
                    if 0 <= (expected_data_size - read_size) <= config.block_size:
                        ecc_resource = await resource.create_child(
                            tags=(FlashEccResource,),
                            data_range=Range(start_index, block_end_offset),
                        )
                        break
        else:
            # With no indicators of the last data block or tail, we fallback to declaring the whole resource ECC protected
            # TODO: Add case for DATA_SIZE appearing in expected offset (block aligned), less chance of false positive
            resource.add_tag(FlashEccResource)
            ecc_resource = resource

        # Parent FlashEccResource is created, add children blocks
        offset = 0
        data = b""
        ecc = b""
        possible_data_len = -sum(
            filter(
                None,
                [
                    -data_len,
                    config.get_block_size(config.header_block_format),
                    config.get_block_size(config.first_data_block_format),
                    config.get_block_size(config.last_data_block_format),
                    config.get_block_size(config.tail_block_format),
                ],
            )
        )
        possible_data_blocks = possible_data_len // config.get_block_size(config.data_block_format)

        for c in [
            config.header_block_format,
            config.first_data_block_format,
            config.data_block_format,
            config.last_data_block_format,
            config.tail_block_format,
        ]:
            if c is not None:
                num_blocks_of_type = 1
                if c is config.data_block_format:
                    num_blocks_of_type = possible_data_blocks
                for x in range(0, num_blocks_of_type):
                    block_size = config.get_block_size(c)
                    block_end_offset = offset + block_size
                    if block_end_offset > data_len:
                        UnpackerError(
                            "Expected complete last block and received less than expected. Input likely malformed"
                        )
                    block_range = Range(offset, block_end_offset)
                    block_data = await ecc_resource.get_data(range=block_range)

                    # Create block as child resource
                    if c is config.header_block_format:
                        tag = FlashEccHeaderBlock
                    elif c is config.tail_block_format:
                        tag = FlashEccTailBlock
                    else:
                        tag = FlashEccBlock
                    await ecc_resource.create_child(
                        tags=(tag,),
                        data_range=block_range,
                    )

                    # Check if there is data in the block
                    block_data_range = config.get_data_range_in_block(c)
                    if block_data_range is not None:
                        data += block_data[block_data_range.start : block_data_range.end]
                    block_ecc_range = config.get_ecc_range_in_block(c)
                    if block_ecc_range is not None:
                        ecc += block_data[block_ecc_range.start : block_ecc_range.end]

                    offset += block_size

        # Add all block data to logical resource for recursive unpacking
        await ecc_resource.create_child(
            tags=(FlashLogicalDataResource,),
            data=data,
        )
        await ecc_resource.create_child(
            tags=(FlashLogicalEccResource,),
            data=ecc,
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
