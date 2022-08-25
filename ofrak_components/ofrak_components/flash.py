from dataclasses import dataclass

from ofrak.component.analyzer import Analyzer
from ofrak.component.unpacker import Unpacker
from ofrak.component.packer import Packer
from ofrak.model.component_model import ComponentConfig
from ofrak.resource_interface import ResourceInterface

SX_ECC_MAGIC: int = b"SXECCv"
FLASH_BLOCK_SIZE = 255
ECC_DATA_DELIMITER = b"*"
ECC_LAST_DATA_BLOCK_DELIMITER = b"$"
ECC_TAIL_BLOCK_DELIMITER = b"!"

#####################
#       ENUMS       #
#####################
class SxEccVersion(Enum):
    ONE = 1


#####################
#     RESOURCES     #
#####################


@dataclass
class FlashResource(GenericBinary):
    size: int
    offset: int

    def get_size(self) -> int:
        return self.size

    def get_offset(self) -> int:
        return self.offset


@dataclass
class FlashEccResource(GenericBinary):
    size: int
    offset: int

    def get_size(self) -> int:
        return self.size

    def get_offset(self) -> int:
        return self.offset

    async def get_header_block(self) -> EccHeaderBlock:
        return await self.resource.get_only_child_as_view(
            EccHeaderBlock,
            ResourceFilter.with_tags(
                EccHeaderBlock,
            ),
        )

    async def get_tail_block(self) -> EccTailBlock:
        return await self.resource.get_only_child_as_view(
            EccTailBlock,
            ResourceFilter.with_tags(
                EccTailBlock,
            ),
        )


class EccHeaderBlock(GenericBinary):
    """
    Start of region protected by ECC
    """

    magic: bytes
    data: bytes
    delimiter: bytes
    ecc: bytes

    def get_magic(self) -> str:
        return str(self.magic)

    def get_delimiter(self) -> str:
        return str(self.delimiter)


class EccBlock(GenericBinary):
    """
    Flash region protected by ECC
    """

    data: bytes
    delimiter: bytes
    ecc: bytes

    def get_delimiter(self) -> str:
        return str(self.delimiter)


class EccTailBlock(GenericBinary):
    """
    End of region protected by ECC
    """

    delimiter: bytes
    protected_size: int
    md5: bytes
    ecc: bytes

    def get_delimiter(self) -> str:
        return str(self.delimiter)

    def get_protected_size(self) -> int:
        return self.protected_size


#####################
#      CONFIGS      #
#####################


@dataclass
class FlashConfig(ComponentConfig):
    pass


#####################
#     ANALYZERS     #
#####################


class FlashAnalyzer(Analyzer[FlashConfig]):
    pass


#####################
#     UNPACKERS     #
#####################


class FlashDataUnpacker(Unpacker[FlashConfig]):
    targets = (FlashResource,)
    children = (
        FlashResource,
        EccHeaderBlock,
        EccBlock,
        EccTailBlock,
    )

    async def unpack(self, resource: Resource, config: FlashConfig):
        flash_data_view: FlashResource = await resource.view_as(FlashResource)


class EccFlashDataUnpacker(Unpacker[None]):
    """
    Unpack regions of flash protected by ECC
    """

    async def unpack(self, resource: Resource, config=None):
        ecc_header_r = await resource.create_child(
            tags=(EccHeaderBlock,), data_range=Range(0, FLASH_BLOCK_SIZE)
        )
        ecc_header = await ecc_header_r.view_as(EccHeaderBlock)
        resource_data = await resource.get_data()

        # Loop through the rest of the blocks, looking for the tail block
        for block_count in range(1, 3):  # TODO: Change to max blocks in the flash
            pass

        print("test")


#####################
#      PACKERS      #
#####################


class FlashDataPacker(Packer[FlashConfig]):
    targets = (FlashResource,)

    async def pack(self, resource: ResourceInterface, config: FlashConfig):
        pass
