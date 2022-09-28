"""
This component is intended to make it easier to analyze raw flash dumps using OFRAK alone.
Most flash dumps have "useful" data mixed in with out-of-band (OOB) data.
The OOB data often includes some Error Correcting Codes (ECC) or checksums.

There are several dataclasses that categorize the sections of the dump:

- `FlashResource` is the overarching resource. The component expects the user to add this tag in order for this component to be run.
    - `FlashOobResource` is the region of `FlashResource` that has OOB data. In the future, there may be multiple of these children resources.
        - `FlashHeaderBlock` is a the first block of a `FlashOobResource`.
        - `FlashBlock` is every block between the header and tail block.
        - `FlashTailBlock` is the final block of a `FlashOobResource`.
        - `FlashLogicalDataResource` is the extracted data only with all of the OOB data removed. This will become a `FlashOobResource` when packed.
        - `FlashLogicalEccResource` is the extracted ECC only. No other OOB data is included.
"""

from dataclasses import dataclass
from hashlib import md5
from enum import Enum
from typing import Any, Callable, Dict, Generator, Iterable, Iterator, Optional

from ofrak import (
    Packer,
    Resource,
    ResourceFilter,
    Unpacker,
)
from ofrak.component.packer import PackerError
from ofrak.component.unpacker import UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentConfig
from ofrak_type.range import Range
from ofrak_components.ecc.abstract import EccError

# Dict of data mapping MD5 checksum to ECC bytes, used to check for updates
DATA_HASHES: Dict[bytes, bytes] = dict()


#####################
#     RESOURCES     #
#####################
@dataclass
class FlashBlock(GenericBinary):
    """
    FlashBlock represents the smallest part of a memory dump.
    Commonly, this is actually a page of memory or a series of pages with OOB data added to the end
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
    FlashHeaderBlock is the first block of a dump.
    It is assumed that there is only a single header block.
    """


@dataclass
class FlashTailBlock(FlashBlock):
    """
    The final block in the dump.
    It is assumed that there is only a single tail block.
    """


@dataclass
class FlashResource(GenericBinary):
    """
    The overarching resource that encapsulates flash storage.
    This will contain a `FlashOobResource` in most cases.
    In the future, support for multiple `FlashOobResource` children should be added.
    """


@dataclass
class FlashOobResource(GenericBinary):
    """
    Represents the region containing Oob data.
    """


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
    The alternate to FlashLogicalDataResource but just includes ECC.
    Does not include any other OOB data.
    Generally less useful on its own but provided anyway.
    """


#####################
#      CONFIGS      #
#####################
@dataclass
class FlashEccConfig(ComponentConfig):
    """
    Must be configured if the resource includes ECC
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
    ALIGNMENT will pad with \x00 bytes by default
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
    FlashConfig is for specifying everything about the specific model of flash.
    The intent is to expand to all common flash configurations.
    Every block has a format specifier to show where each field is in the block as well as the length.
    If there is no OOB data, data_block_format may take this form:

        data_block_format = [FlashField(field_type=FlashFieldType.DATA,size=block_size),]
    """

    """
    Important Notes:
    Assumes that the provided list for each block format is ordered.
    Only define a block_format if they are different from other block formats.
        - A current workaround is adding `FlashField(FlashFieldType.ALIGNMENT, 0)`
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

    def get_num_data_blocks(self, data_len: int, includes_oob: bool = False) -> Iterator[int]:
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
            num_blocks = (
                self.get_num_data_blocks(data_len, includes_oob)
                if c is self.data_block_format
                else 1
            )
            for _ in range(0, num_blocks):
                yield c
                count += 1
        return count

    def get_total_oob_size(self, data_len: int, includes_oob: bool = False) -> int:
        total_oob_size = 0
        for c in self.get_block_formats():
            block_oob_size = self.get_oob_size_in_block(c)
            if block_oob_size is not None:
                num_blocks = (
                    self.get_num_data_blocks(data_len, includes_oob)
                    if c is self.data_block_format
                    else 1
                )
                total_oob_size += block_oob_size * num_blocks
        return total_oob_size

    def get_total_field_size(
        self, data_len: int, field_type: FlashFieldType, includes_oob: bool = False
    ) -> int:
        total_field_size = 0
        for c in self.get_block_formats():
            block_field_size = self.get_field_length_in_block(c, field_type)
            if block_field_size is not None:
                num_blocks = (
                    self.get_num_data_blocks(data_len, includes_oob)
                    if c is self.data_block_format
                    else 1
                )
                total_field_size += block_field_size * num_blocks
        return total_field_size


#####################
#     UNPACKERS     #
#####################
class FlashResourceUnpacker(Unpacker[FlashConfig]):

    targets = (FlashResource,)
    children = (
        FlashOobResource,
        FlashHeaderBlock,
        FlashBlock,
        FlashTailBlock,
        FlashLogicalDataResource,
        FlashLogicalEccResource,
    )

    async def unpack(self, resource: Resource, config: FlashConfig):
        """
        Unpack a raw flash dump using a FlashConfig.

        :param resource:
        :param config: Describes the layout and features found in the flash dump
        :type config: FlashConfig
        """
        ecc_config: FlashEccConfig = config.ecc_config

        start_index = 0
        data = await resource.get_data()
        data_len = len(data)

        if ecc_config is not None:
            magic = ecc_config.ecc_magic
            if magic is not None:
                ecc_magic_offset = data.find(magic)
                if ecc_magic_offset != -1:
                    start_index = ecc_magic_offset

        # Set fallback, in case the current check for the end of the resource fails
        end_offset = data_len

        header_data_size = config.get_field_in_block(
            config.header_block_format, FlashFieldType.DATA_SIZE
        )
        header_total_size = config.get_field_in_block(
            config.header_block_format, FlashFieldType.TOTAL_SIZE
        )
        if config.header_block_format is not None and (
            header_data_size is not None or header_total_size is not None
        ):
            # The header has the size of the entire region including OOB data
            total_ecc_protected_size = 0
            if header_data_size is not None:
                # Found data size in the header, need to calculate expected total size (including OOB)
                data_size_bytes = config.get_field_data_in_block(
                    block_format=config.header_block_format,
                    field_type=FlashFieldType.DATA_SIZE,
                    data=data,
                    block_start_offset=0,
                )
                oob_size = config.get_total_oob_size(data_len=data_len, includes_oob=True)
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
                raise UnpackerError("Expected larger resource than supplied")

            if total_ecc_protected_size > start_index:
                end_offset = start_index + total_ecc_protected_size

        elif config.tail_block_format is not None:
            # Tail has either magic, total_size, or data_size to indicate the end
            tail_magic = config.get_field_in_block(config.tail_block_format, FlashFieldType.MAGIC)
            tail_total_size = config.get_field_in_block(
                config.tail_block_format, FlashFieldType.TOTAL_SIZE
            )
            tail_data_size = config.get_field_in_block(
                config.tail_block_format, FlashFieldType.DATA_SIZE
            )

            if tail_magic is not None:
                end_offset = _get_end_from_magic(config, start_index, data, data_len)
            elif tail_total_size is not None:
                end_offset = _get_end_from_size(
                    config, start_index, data, data_len, FlashFieldType.TOTAL_SIZE
                )
            elif tail_data_size is not None:
                end_offset = _get_end_from_size(
                    config, start_index, data, data_len, FlashFieldType.DATA_SIZE
                )

        # Create the overarching resource
        ecc_resource = await resource.create_child(
            tags=(FlashOobResource,), data_range=Range(start_index, end_offset)
        )

        # Parent FlashEccResource is created, redefine data to limited scope
        data = await ecc_resource.get_data()
        data_len = len(data)

        # Now add children blocks until we reach the tail block
        offset = 0
        only_data = b""
        only_ecc = b""
        for c in config.iterate_through_all_blocks(data_len, True):
            block_size = config.get_block_size(c)
            block_end_offset = offset + block_size
            if block_end_offset > data_len:
                raise UnpackerError("Expected complete block and received less than expected")
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

            block_ecc_range = config.get_field_range_in_block(c, FlashFieldType.ECC)
            if block_ecc_range is not None:
                cur_block_ecc = block_data[block_ecc_range.start : block_ecc_range.end]
                only_ecc += cur_block_ecc
                # Add hash of everything up to the ECC to our dict for faster packing
                block_data_hash = config.checksum_func(block_data[: block_ecc_range.start])
                DATA_HASHES[block_data_hash] = cur_block_ecc

            # Check if there is data in the block
            block_data_range = config.get_field_range_in_block(c, FlashFieldType.DATA)
            if block_data_range is not None:
                if block_ecc_range is not None:
                    # Try decoding/correcting with ECC, otherwise just add the data anyway
                    try:
                        # Assumes that data comes before ECC
                        only_data += ecc_config.ecc_class.decode(block_data[: block_ecc_range.end])[
                            block_data_range.start : block_data_range.end
                        ]
                    except EccError:
                        only_data += block_data[block_data_range.start : block_data_range.end]
                    except TypeError:
                        raise UnpackerError(
                            "Tried to correct with ECC without providing an ecc_class in FlashEccConfig"
                        )
                else:
                    only_data += block_data[block_data_range.start : block_data_range.end]
            offset += block_size

        # Add all block data to logical resource for recursive unpacking
        await ecc_resource.create_child(
            tags=(FlashLogicalDataResource,),
            data=only_data,
        )
        if ecc_config is not None:
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
        """
        :param resource:
        :param config: Describes the layout and features found in the flash dump
        :type config: FlashConfig
        """
        # We want to overwrite ourselves with just the repacked version
        # TODO: Add supoort for multiple FlashOobResource in a dump.
        packed_child = await resource.get_only_child(
            r_filter=ResourceFilter.with_tags(
                FlashOobResource,
            ),
        )
        if packed_child is not None:
            patch_data = await packed_child.get_data()
            original_size = await resource.get_data_length()
            resource.queue_patch(Range(0, original_size), patch_data)


class FlashOobResourcePacker(Packer[FlashConfig]):
    """
    Packs the entire region including Oob data back into a binary blob
    """

    id = b"FlashOobResourcePacker"
    targets = (FlashOobResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        """
        :param resource:
        :param config: Describes the layout and features found in the flash dump
        :type config: FlashConfig
        """
        # We want to overwrite ourselves with just the repacked version
        packed_child = await resource.get_only_child(
            r_filter=ResourceFilter.with_tags(
                FlashOobResource,
            ),
        )
        if packed_child is not None:
            patch_data = await packed_child.get_data()
            original_size = await resource.get_data_length()
            resource.queue_patch(Range(0, original_size), patch_data)


class FlashLogicalDataResourcePacker(Packer[FlashConfig]):
    """
    Packs the `FlashLogicalDataResource` into a `FlashOobResource` of the format
    specified by `config`
    """

    id = b"FlashLogicalDataResourcePacker"
    targets = (FlashLogicalDataResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        """
        :param resource:
        :param config: Describes the layout and features found in the flash dump
        :type config: FlashConfig
        """
        data = await resource.get_data()
        bytes_left = len(data)
        original_size = bytes_left
        packed_data = bytearray()
        data_offset = 0

        for c in config.iterate_through_all_blocks(original_size, False):
            block_data = b""
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

        # Create child under the original FlashOobResource to show that it packed itself
        parent = await resource.get_parent()
        await parent.create_child(tags=(FlashOobResource,), data=packed_data)


#####################
#      HELPERS      #
#####################
def _get_end_from_magic(config: FlashConfig, start_index: int, data: bytes, data_len: int):
    search_offset = start_index
    search_field = FlashFieldType.MAGIC
    search_key = config.ecc_config.ecc_magic

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
            return tail_end_offset
    return data_len


def _get_end_from_size(
    config: FlashConfig, start_index: int, data: bytes, data_len: int, field_type: FlashFieldType
):
    # Only calculates the size if it knows the total size, or data size
    if (field_type is not FlashFieldType.TOTAL_SIZE) and (
        field_type is not FlashFieldType.DATA_SIZE
    ):
        return data_len

    tail_block_size = config.get_block_size(config.tail_block_format)

    cur_offset = start_index
    total_data_size = 0
    read_offset = 0
    for c in config.iterate_through_all_blocks(data_len - start_index, True):
        cur_block_size = config.get_block_size(c)

        # Treat every block as the tail, checking if it has the right field
        cur_block_size_field = config.get_field_data_in_block(
            config.tail_block_format, field_type, data, cur_offset
        )

        if cur_block_size_field is not None:
            read_offset = int.from_bytes(cur_block_size_field, "big")
            end_rel_offset = (cur_offset - start_index) + tail_block_size

            if (
                config.get_field_in_block(config.tail_block_format, FlashFieldType.TOTAL_SIZE)
                is not None
                and read_offset == end_rel_offset
            ) or (
                config.get_field_in_block(config.tail_block_format, FlashFieldType.DATA_SIZE)
                is not None
                and read_offset == total_data_size
            ):
                return cur_offset + tail_block_size
        total_data_size += config.get_field_length_in_block(c, FlashFieldType.DATA)
        cur_offset += cur_block_size
    return data_len


def _build_block(
    cur_block_type: Iterable[FlashField],
    config: FlashConfig,
    block_data: bytes,
    original_data: bytes,
) -> bytes:
    # Update the checksum, even if its not used we use it for tracking if we need it to update ECC
    data_hash = config.checksum_func(block_data)
    ecc_config = config.ecc_config
    if ecc_config is not None:
        ecc_class = ecc_config.ecc_class
        if ecc_class is None:
            raise UnpackerError("Cannot pack FlashLogicalDataResource without providing ECC class")
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
                raise PackerError("Tried to add delimiter without specifying in FlashEccConfig")
        elif f is FlashFieldType.ECC:
            if data_hash in DATA_HASHES:
                ecc = DATA_HASHES[data_hash]
            else:
                # Assumes that all previously added data in the block should be included in the ECC
                # TODO: Support ECC that comes before data
                try:
                    ecc = config.ecc_config.ecc_class.encode(block)
                except TypeError:
                    raise PackerError(
                        "Tried to encode ECC without specifying ecc_class in FlashEccConfig"
                    )
            block += ecc
        elif f is FlashFieldType.ECC_SIZE:
            block_ecc_field = config.get_field_in_block(cur_block_type, FlashFieldType.ECC)
            block += block_ecc_field.size.to_bytes(field.size, "big")
        elif f is FlashFieldType.TOTAL_SIZE:
            data_size = len(original_data)
            oob_size = config.get_total_oob_size(data_len=data_size)
            expected_data_size = config.get_total_field_size(
                data_len=data_size, field_type=FlashFieldType.DATA
            )
            total_size = expected_data_size + oob_size
            block += (total_size).to_bytes(field.size, "big")
        elif f is FlashFieldType.MAGIC:
            try:
                block += config.ecc_config.ecc_magic
            except TypeError:
                raise PackerError("Tried to add Magic without specifying in FlashEccConfig")
    return block
