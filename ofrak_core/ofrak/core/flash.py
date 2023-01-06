"""
This component is intended to make it easier to analyze raw flash dumps using OFRAK alone.
Most flash dumps have "useful" data mixed in with out-of-band (OOB) data.
The OOB data often includes some Error Correcting Codes (ECC) or checksums.

There are several dataclasses that categorize the sections of the dump:

- `FlashResource` is the overarching resource. The component expects the user to add this tag in order for this component to be run.
    - `FlashOobResource` is the region of `FlashResource` that has OOB data. In the future, there may be multiple of these children resources.
        - `FlashLogicalDataResource` is the extracted data only with all of the OOB data removed. This will become a `FlashOobResource` when packed.
        - `FlashLogicalEccResource` is the extracted ECC only. No other OOB data is included.
"""

from dataclasses import dataclass
from enum import Enum
from hashlib import md5
from typing import Any, Callable, Dict, Generator, Iterable, Optional

from ofrak.component.packer import Packer, PackerError
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.core.ecc.abstract import EccAlgorithm, EccError
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

# Dict of data mapping MD5 checksum to ECC bytes, used to check for updates
DATA_HASHES: Dict[bytes, bytes] = dict()


#####################
#     RESOURCES     #
#####################
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
#     ATTRIBUTES    #
#####################
@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class FlashEccAttributes(ResourceAttributes):
    """
    Must be configured if the resource includes ECC
    `ecc_magic` is assumed to be contained at the start of the file, but may also occur multiple times
    """

    ecc_class: Optional[EccAlgorithm] = None
    ecc_magic: Optional[bytes] = None
    head_delimiter: Optional[bytes] = None
    first_data_delimiter: Optional[bytes] = None
    data_delimiter: Optional[bytes] = None
    last_data_delimiter: Optional[bytes] = None
    tail_delimiter: Optional[bytes] = None


class FlashFieldType(Enum):
    """
    `DATA_SIZE` is the packed size of the DATA only (excluding `MAGIC`, `CHECKSUM`, `DELIMITER`, `ECC`, etc)
    `TOTAL_SIZE` is the size of the entire region (including all `DATA`, `MAGIC`, `CHECKSUM`, `DELIMITER`, `ECC`, etc)
    `ALIGNMENT` will pad with \x00 bytes by default
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


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class FlashAttributes(ResourceAttributes):
    """
    FlashAttributes is for specifying everything about the specific model of flash.
    The intent is to expand to all common flash configurations.
    Every block has a format specifier to show where each field is in the block as well as the length.
    If there is no OOB data, data_block_format may take this form:

        data_block_format = [FlashField(field_type=FlashFieldType.DATA,size=block_size),]

    Important Notes:
    Assumes that the provided list for each block format is ordered.
    Only define a block_format if they are different from other block formats.
        - A current workaround is adding `FlashField(FlashFieldType.ALIGNMENT, 0)`
    Assumes that there are only one of each block format except the data_block_format
    """

    data_block_format: Iterable[FlashField]
    header_block_format: Optional[Iterable[FlashField]] = None
    first_data_block_format: Optional[Iterable[FlashField]] = None
    last_data_block_format: Optional[Iterable[FlashField]] = None
    tail_block_format: Optional[Iterable[FlashField]] = None
    ecc_attributes: Optional[FlashEccAttributes] = None
    checksum_func: Optional[Callable[[Any], Any]] = None

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
        if block_format is not None:
            return sum(field.size for field in block_format)
        else:
            return 0

    def get_oob_size_in_block(self, block_format: Iterable[FlashField]) -> int:
        if block_format is None:
            return 0
        data_length = self.get_field_length_in_block(
            block_format=block_format, field_type=FlashFieldType.DATA
        )
        return self.get_block_size(block_format=block_format) - data_length

    def get_field_in_block(
        self, block_format: Optional[Iterable[FlashField]], field_type: FlashFieldType
    ) -> Optional[FlashField]:
        if block_format is None:
            return None
        for field in block_format:
            if field.field_type is field_type:
                return field
        return None

    def get_field_range_in_block(
        self, block_format: Optional[Iterable[FlashField]], field_type: FlashFieldType
    ) -> Optional[Range]:
        offset = 0
        if block_format is None:
            return None
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
        if block_format is None:
            return 0
        field_range = self.get_field_range_in_block(
            block_format=block_format, field_type=field_type
        )
        if field_range is not None:
            return field_range.length()
        return 0

    def get_field_data_in_block(
        self,
        block_format: Optional[Iterable[FlashField]],
        field_type: FlashFieldType,
        data: bytes,
        block_start_offset: int,
    ) -> Optional[bytes]:
        field_range = self.get_field_range_in_block(
            block_format=block_format, field_type=field_type
        )
        if field_range is not None:
            return data[
                block_start_offset + field_range.start : block_start_offset + field_range.end
            ]
        return None

    def get_num_data_blocks(self, data_len: int, includes_oob: bool = False) -> int:
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
class FlashResourceUnpacker(Unpacker[None]):
    """
    Finds the overarching parent for region that includes OOB data.
    Identifies the bounds based on the `FlashAttributes`.
    """

    targets = (FlashResource,)
    children = (FlashOobResource,)

    async def unpack(self, resource: Resource, config=None):
        try:
            flash_attr = resource.get_attributes(FlashAttributes)
        except NotFoundError:
            raise UnpackerError("Tried creating FlashOobResource without FlashAttributes")

        start_index = 0
        data = await resource.get_data()
        data_len = len(data)

        if flash_attr.ecc_attributes is not None:
            magic = flash_attr.ecc_attributes.ecc_magic
            if magic is not None:
                ecc_magic_offset = data.find(magic)

                if ecc_magic_offset == -1:
                    raise UnpackerError("No header magic found")

                magic_range_in_block = flash_attr.get_field_range_in_block(
                    flash_attr.header_block_format, FlashFieldType.MAGIC
                )

                if not magic_range_in_block:
                    raise UnpackerError("Did not find offset for magic in header")

                start_index = ecc_magic_offset - magic_range_in_block.start

        # Set fallback, in case the current check for the end of the resource fails
        end_offset = data_len
        header_data_size = flash_attr.get_field_in_block(
            flash_attr.header_block_format, FlashFieldType.DATA_SIZE
        )
        header_total_size = flash_attr.get_field_in_block(
            flash_attr.header_block_format, FlashFieldType.TOTAL_SIZE
        )
        if flash_attr.header_block_format is not None and (
            header_data_size is not None or header_total_size is not None
        ):
            # The header has the size of the entire region including OOB data
            total_ecc_protected_size = 0
            if header_data_size is not None:
                # Found data size in the header, need to calculate expected total size (including OOB)
                data_size_bytes = flash_attr.get_field_data_in_block(
                    block_format=flash_attr.header_block_format,
                    field_type=FlashFieldType.DATA_SIZE,
                    data=data,
                    block_start_offset=0,
                )
                oob_size = flash_attr.get_total_oob_size(data_len=data_len, includes_oob=True)
                if data_size_bytes is not None:
                    total_ecc_protected_size = oob_size + int.from_bytes(data_size_bytes, "big")
            elif header_total_size is not None:
                # Found total size in header
                total_size_bytes = flash_attr.get_field_data_in_block(
                    block_format=flash_attr.header_block_format,
                    field_type=FlashFieldType.TOTAL_SIZE,
                    data=data,
                    block_start_offset=0,
                )
                if total_size_bytes is not None:
                    total_ecc_protected_size = int.from_bytes(total_size_bytes, "big")

            if total_ecc_protected_size > data_len:
                raise UnpackerError("Expected larger resource than supplied")

            if total_ecc_protected_size > start_index:
                end_offset = start_index + total_ecc_protected_size

        elif flash_attr.tail_block_format is not None:
            # Tail has either magic, total_size, or data_size to indicate the end
            tail_magic = flash_attr.get_field_in_block(
                flash_attr.tail_block_format, FlashFieldType.MAGIC
            )
            tail_total_size = flash_attr.get_field_in_block(
                flash_attr.tail_block_format, FlashFieldType.TOTAL_SIZE
            )
            tail_data_size = flash_attr.get_field_in_block(
                flash_attr.tail_block_format, FlashFieldType.DATA_SIZE
            )

            if tail_magic is not None:
                # we'll start looking after the header to make sure we don't
                # accidentally find the header magic
                if flash_attr.header_block_format:
                    tail_start_index = flash_attr.get_block_size(flash_attr.header_block_format)
                else:
                    tail_start_index = start_index
                end_offset = _get_end_from_magic(flash_attr, tail_start_index, data, data_len)
            elif tail_total_size is not None:
                end_offset = _get_end_from_size(
                    flash_attr, start_index, data, data_len, FlashFieldType.TOTAL_SIZE
                )
            elif tail_data_size is not None:
                end_offset = _get_end_from_size(
                    flash_attr, start_index, data, data_len, FlashFieldType.DATA_SIZE
                )

        # Create the overarching resource
        return await resource.create_child(
            tags=(FlashOobResource,),
            data_range=Range(start_index, end_offset),
            attributes=[
                flash_attr,
            ],
        )


class FlashOobResourceUnpacker(Unpacker[None]):
    """
    Unpack a single `FlashOobResource` dump into logical data using the `FlashAttributes`.
    """

    targets = (FlashOobResource,)
    children = (
        FlashLogicalDataResource,
        FlashLogicalEccResource,
    )

    async def unpack(self, resource: Resource, config=None):
        try:
            flash_attr = resource.get_attributes(FlashAttributes)
        except NotFoundError:
            raise UnpackerError("Tried unpacking without FlashAttributes")
        ecc_attr: Optional[FlashEccAttributes] = flash_attr.ecc_attributes

        # oob_resource = _create_oob_resource(resource=resource)
        oob_resource = resource
        # Parent FlashEccResource is created, redefine data to limited scope
        data = await oob_resource.get_data()
        data_len = len(data)

        # Now add children blocks until we reach the tail block
        offset = 0
        only_data = b""
        only_ecc = b""
        for c in flash_attr.iterate_through_all_blocks(data_len, True):
            block_size = flash_attr.get_block_size(c)
            block_end_offset = offset + block_size
            if block_end_offset > data_len:
                raise UnpackerError("Expected complete block and received less than expected")
            block_range = Range(offset, block_end_offset)
            block_data = await oob_resource.get_data(range=block_range)

            block_ecc_range = flash_attr.get_field_range_in_block(c, FlashFieldType.ECC)
            if block_ecc_range is not None:
                cur_block_ecc = block_data[block_ecc_range.start : block_ecc_range.end]
                only_ecc += cur_block_ecc
                # Add hash of everything up to the ECC to our dict for faster packing
                block_data_hash = md5(block_data[: block_ecc_range.start]).digest()
                DATA_HASHES[block_data_hash] = cur_block_ecc

            # Check if there is data in the block
            block_data_range = flash_attr.get_field_range_in_block(c, FlashFieldType.DATA)
            if block_data_range is not None:
                if block_ecc_range is not None:
                    # Try decoding/correcting with ECC, otherwise just add the data anyway
                    try:
                        # Assumes that data comes before ECC
                        if ecc_attr is not None and ecc_attr.ecc_class is not None:
                            only_data += ecc_attr.ecc_class.decode(
                                block_data[: block_ecc_range.end]
                            )[block_data_range.start : block_data_range.end]
                        else:
                            raise UnpackerError(
                                "Tried to correct with ECC without providing an ecc_class in FlashEccAttributes"
                            )
                    except EccError:
                        only_data += block_data[block_data_range.start : block_data_range.end]
                else:
                    only_data += block_data[block_data_range.start : block_data_range.end]
            offset += block_size

        # Add all block data to logical resource for recursive unpacking
        await oob_resource.create_child(
            tags=(FlashLogicalDataResource,),
            data=only_data,
            attributes=[
                flash_attr,
            ],
        )
        if ecc_attr is not None:
            await oob_resource.create_child(
                tags=(FlashLogicalEccResource,),
                data=only_ecc,
                attributes=[
                    ecc_attr,
                ],
            )


#####################
#      PACKERS      #
#####################
class FlashResourcePacker(Packer[None]):
    """
    Packs the FlashResource into binary and cleans up logical data representations
    """

    id = b"FlashResourcePacker"
    targets = (FlashResource,)

    async def pack(self, resource: Resource, config=None):
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


class FlashOobResourcePacker(Packer[None]):
    """
    Packs the entire region including Oob data back into a binary blob
    """

    id = b"FlashOobResourcePacker"
    targets = (FlashOobResource,)

    async def pack(self, resource: Resource, config=None):
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


class FlashLogicalDataResourcePacker(Packer[None]):
    """
    Packs the `FlashLogicalDataResource` into a `FlashOobResource` of the format
    specified by the `FlashAttributes`
    """

    id = b"FlashLogicalDataResourcePacker"
    targets = (FlashLogicalDataResource,)

    async def pack(self, resource: Resource, config=None):
        try:
            flash_attr = resource.get_attributes(FlashAttributes)
        except NotFoundError:
            raise UnpackerError("Tried packing without FlashAttributes")
        data = await resource.get_data()
        bytes_left = len(data)
        original_size = bytes_left
        packed_data = bytearray()
        data_offset = 0

        for c in flash_attr.iterate_through_all_blocks(original_size, False):
            block_data = b""
            block_data_size = flash_attr.get_field_length_in_block(c, FlashFieldType.DATA)
            if block_data_size != 0:
                # Get the data for the current block
                block_data = data[data_offset : data_offset + block_data_size]
                data_offset += block_data_size
                bytes_left -= block_data_size

            packed_data += _build_block(
                cur_block_type=c,
                attributes=flash_attr,
                block_data=block_data,
                original_data=data,
            )

        # Create child under the original FlashOobResource to show that it packed itself
        parent = await resource.get_parent()
        await parent.create_child(tags=(FlashOobResource,), data=packed_data)


#####################
#      HELPERS      #
#####################
def _get_end_from_magic(attributes: FlashAttributes, start_index: int, data: bytes, data_len: int):
    search_offset = start_index
    search_field = FlashFieldType.MAGIC
    if (
        attributes is None
        or attributes.tail_block_format is None
        or attributes.ecc_attributes is None
    ):
        raise UnpackerError("Tried to find magic without all attributes defined")

    search_key = attributes.ecc_attributes.ecc_magic
    if search_key is None:
        raise UnpackerError(
            "Tried to find magic in tail without providing attribute in FlashEccAttributes"
        )

    while 0 <= search_offset <= data_len:
        search_offset = data.find(search_key, search_offset, data_len)
        if search_offset == -1:
            break

        field_range_in_block = attributes.get_field_range_in_block(
            attributes.tail_block_format, search_field
        )
        if field_range_in_block is not None:
            tail_start_offset = search_offset - field_range_in_block.start
            tail_read_magic = attributes.get_field_data_in_block(
                attributes.tail_block_format, search_field, data, tail_start_offset
            )
            if tail_read_magic == search_key:
                tail_block_size = attributes.get_block_size(attributes.tail_block_format)
                tail_end_offset = tail_start_offset + tail_block_size
                return tail_end_offset

        search_offset += 1
    return data_len


def _get_end_from_size(
    attributes: FlashAttributes,
    start_index: int,
    data: bytes,
    data_len: int,
    field_type: FlashFieldType,
):
    # Only calculates the size if it knows the total size, or data size
    if (field_type is not FlashFieldType.TOTAL_SIZE) and (
        field_type is not FlashFieldType.DATA_SIZE
    ):
        return data_len

    if attributes.tail_block_format is None:
        raise UnpackerError("Tried to find end of resource without providing tail block format")
    tail_block_size = attributes.get_block_size(attributes.tail_block_format)

    cur_offset = start_index
    total_data_size = 0
    read_offset = 0
    for c in attributes.iterate_through_all_blocks(data_len - start_index, True):
        cur_block_size = attributes.get_block_size(c)

        # Treat every block as the tail, checking if it has the right field
        cur_block_size_field = attributes.get_field_data_in_block(
            attributes.tail_block_format, field_type, data, cur_offset
        )

        if cur_block_size_field is not None:
            read_offset = int.from_bytes(cur_block_size_field, "big")
            end_rel_offset = (cur_offset - start_index) + tail_block_size

            if (
                attributes.get_field_in_block(
                    attributes.tail_block_format, FlashFieldType.TOTAL_SIZE
                )
                is not None
                and read_offset == end_rel_offset
            ) or (
                attributes.get_field_in_block(
                    attributes.tail_block_format, FlashFieldType.DATA_SIZE
                )
                is not None
                and read_offset == total_data_size
            ):
                return cur_offset + tail_block_size
        total_data_size += attributes.get_field_length_in_block(c, FlashFieldType.DATA)
        cur_offset += cur_block_size
    return data_len


def _build_block(
    cur_block_type: Iterable[FlashField],
    attributes: FlashAttributes,
    block_data: bytes,
    original_data: bytes,
) -> bytes:
    # Update the checksum, even if its not used we use it for tracking if we need it to update ECC
    if attributes is None:
        raise UnpackerError("Cannot pack without providing FlashAttributes")
    data_hash = md5(block_data).digest()
    ecc_attr = attributes.ecc_attributes
    block = b""
    if ecc_attr is not None:
        ecc_class = ecc_attr.ecc_class
        if ecc_class is None:
            raise UnpackerError("Cannot pack FlashLogicalDataResource without providing ECC class")
        for field in cur_block_type:
            if field is not None:
                f = field.field_type
                f_size = field.size
                if f is FlashFieldType.ALIGNMENT:
                    block += b"\x00" * f_size
                elif f is FlashFieldType.CHECKSUM:
                    if attributes.checksum_func is not None:
                        block += attributes.checksum_func(original_data)
                elif f is FlashFieldType.DATA:
                    expected_data_size = attributes.get_field_length_in_block(
                        cur_block_type, FlashFieldType.DATA
                    )
                    real_data_len = len(block_data)
                    if real_data_len < expected_data_size:
                        cur_block_data = bytearray(expected_data_size)
                        cur_block_data[:real_data_len] = block_data
                        block_data = cur_block_data
                    block += block_data
                elif f is FlashFieldType.DATA_SIZE:
                    block += len(original_data).to_bytes(f_size, "big")
                elif f is FlashFieldType.DELIMITER:
                    if cur_block_type == attributes.header_block_format:
                        delimiter = ecc_attr.head_delimiter
                    elif cur_block_type == attributes.first_data_block_format:
                        delimiter = ecc_attr.first_data_delimiter
                    elif cur_block_type == attributes.data_block_format:
                        delimiter = ecc_attr.data_delimiter
                    elif cur_block_type == attributes.last_data_block_format:
                        delimiter = ecc_attr.last_data_delimiter
                    elif cur_block_type == attributes.tail_block_format:
                        delimiter = ecc_attr.tail_delimiter
                    else:
                        raise PackerError(
                            "Tried to add delimiter without specifying in FlashEccAttributes"
                        )
                    if delimiter is not None:
                        block += delimiter
                elif f is FlashFieldType.ECC:
                    if data_hash in DATA_HASHES:
                        ecc = DATA_HASHES[data_hash]
                    else:
                        # Assumes that all previously added data in the block should be included in the ECC
                        # TODO: Support ECC that comes before data
                        try:
                            if ecc_attr.ecc_class is not None:
                                ecc = ecc_attr.ecc_class.encode(block)
                        except TypeError:
                            raise PackerError(
                                "Tried to encode ECC without specifying ecc_class in FlashEccAttributes"
                            )
                    block += ecc
                elif f is FlashFieldType.ECC_SIZE:
                    block_ecc_field = attributes.get_field_in_block(
                        cur_block_type, FlashFieldType.ECC
                    )
                    if block_ecc_field is not None:
                        block += block_ecc_field.size.to_bytes(f_size, "big")
                elif f is FlashFieldType.TOTAL_SIZE:
                    data_size = len(original_data)
                    oob_size = attributes.get_total_oob_size(data_len=data_size)
                    expected_data_size = attributes.get_total_field_size(
                        data_len=data_size, field_type=FlashFieldType.DATA
                    )
                    total_size = expected_data_size + oob_size
                    block += (total_size).to_bytes(f_size, "big")
                elif f is FlashFieldType.MAGIC:
                    if ecc_attr.ecc_magic is None:
                        raise PackerError(
                            "Tried to add Magic without specifying in FlashEccAttributes"
                        )
                    block += ecc_attr.ecc_magic
    return block
