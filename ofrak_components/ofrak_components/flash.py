import io
from dataclasses import dataclass

from ofrak import Analyzer, Unpacker, Packer, Resource, Identifier
from ofrak.model.component_model import ComponentConfig
from ofrak_type.range import Range
from ofrak.component.unpacker import UnpackerError
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_type.endianness import Endianness
from ofrak.core import (
    GenericBinary,
)

SX_ECC_MAGIC: int = b"SXECCv1"
SX_ECC_MAGIC_LEN: int = len(SX_ECC_MAGIC)
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
class FlashData(GenericBinary):
    """
    This is the valuable data held in flash storage.
    """


@dataclass
class FlashEcc(GenericBinary):
    """
    ECC is some out of bounds data stored in flash.
    It should be stripped away from the data to make it usable.
    """


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

    def get_data(self) -> bytes:
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

    def get_data(self) -> bytes:
        return self.data

    def get_delimiter(self) -> bytes:
        return self.delimiter

    def get_ecc(self) -> bytes:
        return self.ecc


@dataclass
class FlashEccLastBlock(GenericBinary):
    data: bytes
    delimiter: bytes
    ecc: bytes

    def get_data(self) -> bytes:
        return self.data

    def get_delimiter(self) -> bytes:
        return self.delimiter

    def get_ecc(self) -> bytes:
        return self.ecc


@dataclass
class FlashEccTailBlock(GenericBinary):
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
    async def get_ecc_header_block(self) -> FlashEccHeaderBlock:
        return await self.resource.get_children(
            FlashEccHeaderBlock, Resource.Filter.with_tags(FlashEccHeaderBlock)
        )

    async def get_ecc_block(self) -> FlashEccBlock:
        return await self.resource.get_children(
            FlashEccBlock, Resource.Filter.with_tags(FlashEccBlock)
        )

    async def get_ecc_last_block(self) -> FlashEccLastBlock:
        return await self.resource.get_children(
            FlashEccLastBlock, Resource.Filter.with_tags(FlashEccLastBlock)
        )

    async def get_ecc_tail_block(self) -> FlashEccTailBlock:
        return await self.resource.get_children(
            FlashEccTailBlock, Resource.Filter.with_tags(FlashEccTailBlock)
        )

    async def get_data(self) -> FlashData:
        return await self.resource.get_children(FlashData, Resource.Filter.with_tags(FlashData))

    async def get_ecc(self) -> FlashEcc:
        return await self.resource.get_children(FlashEcc, Resource.Filter.with_tags(FlashEcc))


class FlashResource(GenericBinary):
    """
    The overarching resource that encapsulates flash storage.
    This is made up of several blocks.
    """

    size: int

    def get_size(self) -> int:
        return self.size

    async def get_data(self) -> FlashData:
        return await self.resource.get_children(FlashData, Resource.Filter.with_tags(FlashData))

    async def get_ecc(self) -> FlashEcc:
        return await self.resource.get_children(FlashEcc, Resource.Filter.with_tags(FlashEcc))


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
    targets = (FlashResource,)

    async def identify(self, resource: Resource, config=None):
        data = await resource.get_data()
        if SX_ECC_MAGIC in data:
            resource.add_tag(FlashEccResource)


#####################
#     ANALYZERS     #
#####################
class FlashResourceAnalyzer(Analyzer[None, FlashResource]):
    targets = (FlashResource,)
    outputs = (FlashResource,)

    async def analyze(self, resource: Resource, config=None) -> FlashResource:
        data_len = await resource.get_data_length()
        return FlashResource(
            data_len,
        )


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
class FlashEccResourceUnpacker(Unpacker[None]):
    """
    Unpack regions of flash protected by ECC
    """

    targets = (FlashEccResource,)
    children = (
        FlashEccHeaderBlock,
        FlashEccBlock,
        FlashEccLastBlock,
        FlashEccTailBlock,
        FlashData,
        FlashEcc,
    )

    async def unpack(self, resource: Resource, config=None):
        data = await resource.get_data()
        ecc_magic_offset = data.find(SX_ECC_MAGIC)
        last_block_flag = False
        num_possible_ecc_blocks = len(data[ecc_magic_offset:]) // FLASH_BLOCK_SIZE
        for block_count in range(0, num_possible_ecc_blocks):
            cur_block_offset = ecc_magic_offset + (FLASH_BLOCK_SIZE * block_count)
            print(hex(cur_block_offset))
            cur_block_end_offset = cur_block_offset + FLASH_BLOCK_SIZE
            cur_block_data = data[cur_block_offset:cur_block_end_offset]
            cur_block_delimiter = cur_block_data[ECC_BLOCK_DATA_SIZE : ECC_BLOCK_DATA_SIZE + 1]
            if cur_block_delimiter == ECC_DATA_DELIMITER:
                if block_count == 0:
                    # Verify ECC header block to confirm there is a protected region
                    if data[cur_block_offset : cur_block_offset + SX_ECC_MAGIC_LEN] != SX_ECC_MAGIC:
                        raise UnpackerError("Bad ECC Magic")

                    header_block = await resource.create_child(
                        tags=(FlashEccHeaderBlock,),
                        data_range=Range(cur_block_offset, cur_block_end_offset),
                    )
                    await header_block.create_child(
                        tags=(FlashData,),
                        data_range=Range(SX_ECC_MAGIC_LEN, ECC_HEADER_DELIMITER_OFFSET),
                    )
                    await header_block.create_child(
                        tags=(FlashEcc,),
                        data_range=Range(ECC_HEADER_DELIMITER_OFFSET + 1, FLASH_BLOCK_SIZE),
                    )
                else:
                    # Regular data block
                    data_block = await resource.create_child(
                        tags=(FlashEccBlock,),
                        data_range=Range(cur_block_offset, cur_block_end_offset),
                    )
                    await data_block.create_child(
                        tags=(FlashData,),
                        data_range=Range(0, ECC_BLOCK_DATA_SIZE),
                    )
                    await data_block.create_child(
                        tags=(FlashEcc,),
                        data_range=Range(ECC_BLOCK_DATA_SIZE + 1, FLASH_BLOCK_SIZE),
                    )
            elif cur_block_delimiter == ECC_LAST_DATA_BLOCK_DELIMITER:
                # This is the last data block, prepare for tail block
                last_block_flag = True

                data_block = await resource.create_child(
                    tags=(FlashEccLastBlock,),
                    data_range=Range(cur_block_offset, cur_block_end_offset),
                )
                await data_block.create_child(
                    tags=(FlashData,),
                    data_range=Range(0, ECC_BLOCK_DATA_SIZE),
                )
                await data_block.create_child(
                    tags=(FlashEcc,),
                    data_range=Range(ECC_BLOCK_DATA_SIZE + 1, FLASH_BLOCK_SIZE),
                )
            elif last_block_flag:
                print("Last block")
                if cur_block_data[0:1] == ECC_TAIL_BLOCK_DELIMITER:
                    tail_block = await resource.create_child(
                        tags=(FlashEccTailBlock,),
                        data_range=Range(cur_block_offset, cur_block_offset + ECC_TAIL_BLOCK_SIZE),
                    )
                    await tail_block.create_child(
                        tags=(FlashEcc,),
                        data_range=Range(ECC_TAIL_BLOCK_SIZE - ECC_SIZE, ECC_TAIL_BLOCK_SIZE),
                    )
                break
            else:
                UnpackerError("Bad Flash ECC Delimiter")
                break

        print("Exited unpacker for loop")


#####################
#      PACKERS      #
#####################
class FlashResourcePacker(Packer[FlashConfig]):
    targets = (FlashResource,)

    async def pack(self, resource: Resource, config: FlashConfig):
        pass
