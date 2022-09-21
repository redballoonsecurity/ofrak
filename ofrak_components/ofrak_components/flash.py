from dataclasses import dataclass
from hashlib import md5
from enum import Enum
from typing import Any, Callable, Dict, Iterable, Optional, Iterator, Generator

from ofrak import (
    Identifier,
    Packer,
    Resource,
    ResourceFilter,
    Unpacker,
)
from ofrak.component.identifier import IdentifierError
from ofrak.component.packer import PackerError
from ofrak.component.unpacker import UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentConfig
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

# Dict of data MD5 checksum to ECC bytes, used to check for updates
DATA_HASHES: Dict[bytes, bytes] = dict()


#####################
#     RESOURCES     #
#####################
@dataclass
class FlashBlock(GenericBinary):
    """
    FlashBlock makes up a small portion of the flash.
    Inside of a flash block is either just data or data + ECC.
    """

    data: Optional[bytes] = None
    ecc: Optional[bytes] = None
    alignment: Optional[bytes] = None
    magic: Optional[bytes] = None
    data_size: Optional[int] = None
    ecc_size: Optional[int] = None
    checksum: Optional[bytes] = None
    delimiter: Optional[bytes] = None
    total_size: Optional[int] = None


@dataclass
class FlashHeaderBlock(FlashBlock):
    """
    FlashBlock makes up a small portion of the flash.
    Inside of a flash block is either just data or data + ECC.
    """


@dataclass
class FlashTailBlock(FlashBlock):
    """
    The final block in the ECC marked region
    """


@dataclass
class FlashResource(GenericBinary):
    """
    The overarching resource that encapsulates flash storage.
    This is made up of several blocks.
    """


@dataclass
class FlashEccProtectedResource(FlashResource):
    """
    Region of memory protected by ECC
    """


@dataclass
class FlashEccResource(FlashEccProtectedResource):
    """
    Overarching resource for physical representation containing FlashEccBlocks
    """


@dataclass
class FlashLogicalDataResource(FlashResource):
    """
    This is the final product of unpacking a FlashResource.
    It contains the data without any ECC or OOB data included.
    This allows for recursive packing and unpacking.
    """


@dataclass
class FlashLogicalEccResource(FlashResource):
    """
    The alternate to FlashLogicalDataResource.
    Generally less useful on its own but provided anyway.
    """


#####################
#      CONFIGS      #
#####################
@dataclass
class FlashEccConfig(ComponentConfig):
    """
    Must be configured if the Flash has ECC protection
    ecc_magic is assumed to be contained at the start of the file, but may also occur multiple times
    """

    ecc_class: Callable[[Any], Any]
    ecc_magic: Optional[bytes] = None
    head_delimiter: Optional[bytes] = None
    first_data_delimiter: Optional[bytes] = None
    data_delimiter: Optional[bytes] = None
    last_data_delimiter: Optional[bytes] = None
    tail_delimiter: Optional[bytes] = None


class FlashFieldType(Enum):
    """
    DATA_SIZE is the packed size of the DATA only (excluding MAGIC, CHECKSUM, DELIMITER, ECC, etc)
    TOTAL_SIZE is the size of the entire region (including all DATA, MAGIC, CHECKSUM, DELIMITER, ECC, etc)
    """

    DATA = 0
    ECC = 1
    ALIGNMENT = 2
    MAGIC = 3
    DATA_SIZE = 4
    ECC_SIZE = 5
    CHECKSUM = 6
    DELIMITER = 7
    TOTAL_SIZE = 8


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

    Important Notes:
    Assumes that the provided list for each block format is ordered
    Only define first_data_block_format and last_data_block_format if they are different from data_block_format
        - A current workaround is adding FlashField(FlashFieldType.ALIGNMENT, 0)
    Assumes that there are only one of each block format except the data_block_format
    The checksum function will be used repeatedly internally for saving on encoding saved ECC values for each block
    """

    data_block_format: Iterable[FlashField]
    header_block_format: Optional[Iterable[FlashField]] = None
    first_data_block_format: Optional[Iterable[FlashField]] = None
    last_data_block_format: Optional[Iterable[FlashField]] = None
    tail_block_format: Optional[Iterable[FlashField]] = None
    ecc_config: Optional[FlashEccConfig] = None
    checksum_func: Optional[Callable[[Any], Any]] = lambda x: md5(x).digest()

    def get_block_formats(self) -> Iterable:
        return filter(
            None,
            [
                self.header_block_format,
                self.first_data_block_format,
                self.data_block_format,
                self.last_data_block_format,
                self.tail_block_format,
            ],
        )

    def get_block_size(self, block_format: Iterable[FlashField]) -> int:
        size = 0
        if block_format is not None:
            for field in block_format:
                size += field.size
        return size

    def get_oob_size_in_block(self, block_format: Iterable[FlashField]) -> int:
        if block_format is not None:
            data_length = self.get_field_length_in_block(
                block_format=block_format, field_type=FlashFieldType.DATA
            )
            return self.get_block_size(block_format=block_format) - data_length
        return 0

    def get_field_in_block(
        self, block_format: Iterable[FlashField], field_type: FlashFieldType
    ) -> FlashField:
        if block_format is not None:
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

    def get_field_length_in_block(
        self, block_format: Iterable[FlashField], field_type: FlashFieldType
    ) -> int:
        if block_format is not None:
            field_range = self.get_field_range_in_block(
                block_format=block_format, field_type=field_type
            )
            if field_range is not None:
                return field_range.length()
        return 0

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
        if field_range is not None:
            return data[
                block_start_offset + field_range.start : block_start_offset + field_range.end
            ]
        return None

    def get_num_data_blocks(self, data_len: int, includes_oob: bool) -> Iterator[int]:
        data_block_count = 0
        data_count = 0
        for c in self.get_block_formats():
            if c != self.data_block_format:
                # Skip data block for now
                if includes_oob:
                    block_data_len = self.get_block_size(c)
                else:
                    block_data_len = self.get_field_length_in_block(c, FlashFieldType.DATA)

                if block_data_len is not None:
                    data_count += block_data_len

        if includes_oob:
            block_data_len = self.get_block_size(self.data_block_format)
        else:
            block_data_len = self.get_field_length_in_block(
                self.data_block_format, FlashFieldType.DATA
            )

        while data_count < data_len:
            # The rest of the blocks are data blocks
            data_count += block_data_len
            data_block_count += 1
        return data_block_count

    def iterate_through_all_blocks(
        self, data_len: int, includes_oob: bool
    ) -> Generator[Iterable[FlashField], None, int]:
        count = 0
        for c in self.get_block_formats():
            num_blocks_of_type = 1
            if c == self.data_block_format:
                num_blocks_of_type = self.get_num_data_blocks(data_len, includes_oob)

            for _ in range(0, num_blocks_of_type):
                yield c
                count += 1
        return count

    def get_total_oob_size(self, data_len: int) -> int:
        total_oob_size = 0
        for c in self.get_block_formats():
            block_oob_size = self.get_oob_size_in_block(c)
            if block_oob_size is not None:
                num_blocks = 1
                if c is self.data_block_format:
                    num_blocks = self.get_num_data_blocks(data_len)
                for _ in range(0, num_blocks):
                    total_oob_size += block_oob_size
        return total_oob_size

    def get_total_field_size(self, data_len: int, field_type: FlashFieldType) -> int:
        total_field_size = 0
        for c in self.get_block_formats():
            block_field_size = self.get_field_length_in_block(c, field_type)
            if block_field_size is not None:
                num_blocks = 1
                if c == self.data_block_format:
                    num_blocks = self.get_num_data_blocks(data_len)
                for _ in range(0, num_blocks):
                    total_field_size += block_field_size
        return total_field_size


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
#     UNPACKERS     #
#####################
class FlashEccProtectedResourceUnpacker(Unpacker[FlashConfig]):
    """
    Unpack regions of flash protected by ECC
    """

    targets = (FlashEccProtectedResource,)
    children = (
        FlashEccResource,
        FlashHeaderBlock,
        FlashBlock,
        FlashTailBlock,
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

        # Set fallback, in case the current check for the end of the resource fails
        ecc_resource = resource

        header_data_size = config.get_field_in_block(
            config.header_block_format, FlashFieldType.DATA_SIZE
        )
        header_total_size = config.get_field_in_block(
            config.header_block_format, FlashFieldType.TOTAL_SIZE
        )
        tail_magic = config.get_field_in_block(config.tail_block_format, FlashFieldType.MAGIC)
        tail_data_size = config.get_field_in_block(
            config.tail_block_format, FlashFieldType.DATA_SIZE
        )
        tail_total_size = config.get_field_in_block(
            config.tail_block_format, FlashFieldType.TOTAL_SIZE
        )
        if config.header_block_format is not None and (
            header_data_size is not None or header_total_size is not None
        ):
            # The header has the size of the ECC protected region
            total_ecc_protected_size = 0
            if header_data_size is not None:
                # Found data size in the header, need to calculate expected total size (including OOB)
                data_size_bytes = config.get_field_data_in_block(
                    block_format=config.header_block_format,
                    field_type=FlashFieldType.DATA_SIZE,
                    data=data,
                    block_start_offset=0,
                )
                oob_size = (config.get_oob_size_in_block(c) for c in config.get_block_formats())
                total_ecc_protected_size = oob_size + int.from_bytes(data_size_bytes, "big")
            elif header_total_size is not None:
                # Found total size in header
                total_size_bytes = config.get_field_data_in_block(
                    block_format=config.header_block_format,
                    field_type=FlashFieldType.TOTAL_SIZE,
                    data=data,
                    block_start_offset=0,
                )
                total_ecc_protected_size = int.from_bytes(total_size_bytes, "big")

            if total_ecc_protected_size > data_len:
                UnpackerError("Expected larger resource than supplied")

            if total_ecc_protected_size > start_index:
                ecc_resource = await resource.create_child(
                    tags=(FlashEccResource,),
                    data_range=Range(start_index, start_index + total_ecc_protected_size),
                )

        elif config.tail_block_format is not None:
            # Not assuming that the end of the data is the end of the ECC protected region
            if tail_magic is not None:
                # Found magic bytes
                search_offset = start_index
                search_field = FlashFieldType.MAGIC
                search_key = ecc_config.ecc_magic

                while 0 <= search_offset <= data_len:
                    search_offset = data.find(search_key, search_offset, data_len)
                    search_offset += 1

                    search_offset_in_block = config.get_field_range_in_block(
                        config.tail_block_format, search_field
                    )
                    tail_start_offset = search_offset - search_offset_in_block.start
                    tail_read_magic = config.get_field_data_in_block(
                        config.tail_block_format, search_field, data, tail_start_offset
                    )

                    if tail_read_magic == search_key:
                        tail_block_size = config.get_block_size(config.tail_block_format)
                        tail_end_offset = tail_start_offset + tail_block_size
                        ecc_resource = await resource.create_child(
                            tags=(FlashEccResource,), data_range=Range(start_index, tail_end_offset)
                        )
                        break

            elif tail_total_size is not None or tail_data_size is not None:
                # Size is in the tail, we just need to go to that location and confirm its offset
                tail_block_size = config.get_block_size(config.tail_block_format)

                cur_offset = start_index
                total_oob_size = 0
                read_offset = 0
                for c in config.iterate_through_all_blocks(data_len - start_index, True):
                    cur_block_size = config.get_block_size(c)
                    total_oob_size += config.get_oob_size_in_block(c)

                    if tail_total_size is not None:
                        field_type = FlashFieldType.TOTAL_SIZE
                    elif tail_data_size is not None:
                        field_type = FlashFieldType.DATA_SIZE

                    # Treat every block as the tail, checking if it has the right field
                    cur_block_size_field = config.get_field_data_in_block(
                        config.tail_block_format, field_type, data, cur_offset
                    )

                    if cur_block_size_field is not None:
                        read_offset = int.from_bytes(cur_block_size_field, "big")
                        total_size_diff = read_offset - cur_offset
                        if (tail_total_size is not None and total_size_diff <= tail_block_size) or (
                            tail_data_size is not None
                            and total_size_diff - total_oob_size <= tail_block_size
                        ):
                            size_field_offset_in_block = config.get_field_range_in_block(
                                config.tail_block_format, field_type
                            )
                            tail_start_offset = cur_offset - size_field_offset_in_block.start
                            ecc_resource = await resource.create_child(
                                tags=(FlashEccResource,),
                                data_range=Range(
                                    start_index, tail_start_offset + tail_block_size + 1
                                ),
                            )
                            break
                    cur_offset += cur_block_size

        if ecc_resource == resource and start_index != 0:
            # With no indicators of the last data block or tail, we fallback to declaring the whole resource ECC protected
            ecc_resource = await resource.create_child(
                tags=(FlashEccResource,), data_range=Range(start_index, data_len)
            )

        # Parent FlashEccResource is created, redefine data to limited scope
        data = await ecc_resource.get_data()
        data_len = len(data)

        # Now add children blocks
        offset = 0
        only_data = b""
        only_ecc = b""

        for c in config.iterate_through_all_blocks(data_len, True):
            block_size = config.get_block_size(c)
            block_end_offset = offset + block_size
            if block_end_offset > data_len:
                UnpackerError(
                    "Expected complete last block and received less than expected. Input likely malformed"
                )
            block_range = Range(offset, block_end_offset)
            block_data = await ecc_resource.get_data(range=block_range)

            # Create block as child resource
            if c == config.header_block_format:
                tag = FlashHeaderBlock
            elif c == config.tail_block_format:
                tag = FlashTailBlock
            else:
                tag = FlashBlock
            await ecc_resource.create_child(
                tags=(tag,),
                data_range=block_range,
            )

            # Check if there is data in the block
            block_data_range = config.get_field_range_in_block(c, FlashFieldType.DATA)
            if block_data_range is not None:
                # TODO: Support decoding/correcting using ECC
                cur_block_data = block_data[block_data_range.start : block_data_range.end]
                only_data += cur_block_data

            block_ecc_range = config.get_field_range_in_block(c, FlashFieldType.ECC)
            if block_ecc_range is not None:
                cur_block_ecc = block_data[block_ecc_range.start : block_ecc_range.end]
                only_ecc += cur_block_ecc
                # Add hash of everything up to the ECC to our dict for faster packing
                block_data_hash = config.checksum_func(block_data[: block_ecc_range.start])
                DATA_HASHES[block_data_hash] = cur_block_ecc

            offset += block_size

        # Add all block data to logical resource for recursive unpacking
        await ecc_resource.create_child(
            tags=(FlashLogicalDataResource,),
            data=only_data,
        )
        await ecc_resource.create_child(
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

        for c in config.iterate_through_all_blocks(original_size, False):
            block_data_size = config.get_field_length_in_block(c, FlashFieldType.DATA)
            if block_data_size != 0:
                # Get the data for the current block
                block_data = data[data_offset : data_offset + block_data_size]
                data_offset += block_data_size
                bytes_left -= block_data_size

            packed_data += _build_block(
                cur_block_type=c,
                config=config,
                block_data=block_data,
                original_data=data,
            )

        # Create child under the FlashEccResource to show that it packed itself
        parent = await resource.get_parent()
        await parent.create_child(tags=(FlashEccResource,), data=packed_data)


#####################
#      HELPERS      #
#####################
def _build_block(
    cur_block_type: Iterable[FlashField],
    config: FlashConfig,
    block_data: bytes,
    original_data: bytes,
) -> bytes:
    # Update the checksum, even if its not used we use it for tracking if we need it to update ECC
    data_hash = config.checksum_func(block_data)
    block = b""
    for field in cur_block_type:
        f = field.field_type
        if f is FlashFieldType.ALIGNMENT:
            block += b"\x00" * field.size
        elif f is FlashFieldType.CHECKSUM:
            block += config.checksum_func(original_data)
        elif f is FlashFieldType.DATA:
            expected_data_size = config.get_field_length_in_block(
                cur_block_type, FlashFieldType.DATA
            )
            real_data_len = len(block_data)
            if real_data_len < expected_data_size:
                cur_block_data = bytearray(expected_data_size)
                cur_block_data[:real_data_len] = block_data
                block_data = cur_block_data
            block += block_data
        elif f is FlashFieldType.DATA_SIZE:
            block += len(original_data).to_bytes(field.size, "big")
        elif f is FlashFieldType.DELIMITER:
            try:
                if cur_block_type == config.header_block_format:
                    block += config.ecc_config.head_delimiter
                elif cur_block_type == config.first_data_block_format:
                    block += config.ecc_config.first_data_delimiter
                elif cur_block_type == config.data_block_format:
                    block += config.ecc_config.data_delimiter
                elif cur_block_type == config.last_data_block_format:
                    block += config.ecc_config.last_data_delimiter
                elif cur_block_type == config.tail_block_format:
                    block += config.ecc_config.tail_delimiter
            except TypeError:
                PackerError("Tried to add delimiter without specifying in FlashEccConfig")
        elif f is FlashFieldType.ECC:
            if data_hash in DATA_HASHES:
                ecc = DATA_HASHES[data_hash]
            else:
                # Assumes that all previously added data in the block should be included in the ECC
                # TODO: Support ECC that comes before data
                ecc = config.ecc_config.ecc_class.encode(block)
            block += ecc
        elif f is FlashFieldType.ECC_SIZE:
            block_ecc_field = config.get_field_in_block(cur_block_type, FlashFieldType.ECC)
            block += block_ecc_field.size.to_bytes(field.size, "big")
        elif f is FlashFieldType.TOTAL_SIZE:
            data_size = len(original_data)
            oob_size = config.get_total_oob_size(data_len=data_size)
            expected_data_size = config.get_total_field_size(data_size, FlashFieldType.DATA)
            total_size = expected_data_size + oob_size
            block += (total_size).to_bytes(field.size, "big")
        elif f is FlashFieldType.MAGIC:
            block += config.ecc_config.ecc_magic
    return block
