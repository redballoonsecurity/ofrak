import logging
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Iterable, Optional

from ofrak.core.program import Program
from ofrak.core.program_section import NamedProgramSection
from ofrak.model.resource_model import index, ResourceAttributes
from ofrak.service.resource_service_i import (
    ResourceAttributeValueFilter,
    ResourceFilter,
)
from ofrak.model.component_model import ComponentConfig

"""
# ESP-IDF Firmware Image Format Documentation
* Multi-byte fields are little-endian.

## Header:
### ESP8266:
    Consists of a header, multiple data segments and a footer.
    +--------+------------------------------------------------------------------+
    | Byte   | Description                                                      |
    +========+==================================================================+
    | 0      | Magic number (0xE9)                                              |
    +--------+------------------------------------------------------------------+
    | 1      | Number of segments                                               |
    +--------+------------------------------------------------------------------+
    | 2      | SPI Flash Mode (0 = QIO, 1 = QOUT, 2 = DIO, 3 = DOUT)            |
    +--------+------------------------------------------------------------------+
    | 3      | High four bits - Flash size (0=512KB,1=256KB,2=1MB,3=2MB,4=4MB,  |
    |        |                              5=2MB-c1,6=4MB-c1,8=8MB,9=16MB) |   |
    |        | Low four bits - Flash frequency (0 = 40MHz, 1 = 26MHz, 2 = 20MHz,|
    |        |                                  0xf = 80MHz)                    |
    +--------+------------------------------------------------------------------+
    | 4-7    | Entry point address                                              |
    +--------+------------------------------------------------------------------+
    Individual segments come right after this header.

### ESP32:
    * Consists of a header, extended header, multiple data segments and a footer.
    * ITFF_0, ITFF_1, ITFF_2, ITFF_F are the IDF Target Flash Frequencies in MHz.

#### Extended File Header:
    The 16-byte extended header right after image header, then segments:
    +--------+------------------------------------------------------------------+
    | Byte   | Description                                                      |
    +========+==================================================================+
    | 0      | WP pin when SPI pins set via efuse (read by ROM bootloader)      |
    +--------+------------------------------------------------------------------+
    | 1-3    | Drive settings for the SPI flash pins (read by ROM bootloader)   |
    +--------+------------------------------------------------------------------+
    | 4-5    | Chip ID (which ESP device is this image for)                     |
    +--------+------------------------------------------------------------------+
    | 6      | Min chip rev supported by image (deprecated, use following field)|
    +--------+------------------------------------------------------------------+
    | 7-8    | Min chip rev supported by the image (in format: major*100+minor) |
    +--------+------------------------------------------------------------------+
    | 9-10   | Max chip rev supported by the image (in format: major*100+minor) |
    +--------+------------------------------------------------------------------+
    | 11-14  | Reserved bytes in additional header space, currently unused      |
    +--------+------------------------------------------------------------------+
    | 15     | Hash appended (If 1, SHA256 digest appended after the checksum)  |
    +--------+------------------------------------------------------------------+
    Note: the spi drive settings are auto parsed into clk_drv, q_drv, d_drv,
    cs_drv, hd_drv, and wp_drv.

## Segment:
    +---------+-----------------+
    | Byte    | Description     |
    +=========+=================+
    | 0-3     | Memory offset   |
    +---------+-----------------+
    | 4-7     | Segment size    |
    +---------+-----------------+
    | 8...n   | Data            |
    +---------+-----------------+

## Footer:
The file is padded with zeros until its size is one byte less than a multiple of
16 bytes. A last byte (thus making the file size a multiple of 16) is the
checksum of the data of all segments. The checksum is defined as the xor-sum of
all bytes and the byte ``0xEF``.

### Not in ESP8266:
    If ``hash appended`` in the extended file header is ``0x01``, a SHA256
    digest "simple hash" (of the entire image) is appended after the checksum.
    This digest is separate to secure boot and only used for detecting
    corruption.
"""

LOGGER = logging.getLogger(__name__)

ESP_APP_MAGIC = 0xE9
ESP8266V2_APP_MAGIC = 0xEA  # In the esptool.py code, but haven't seen it in the documentation
ESP_APP_HEADER_SIZE = 8
ESP_APP_EXTENDED_HEADER_SIZE = 16
ESP_APP_SEGMENT_HEADER_SIZE = 8
ESP_APP_DESCRIPTION_MAGIC_WORD = 0xABCD5432
ESP_APP_CHECKSUM_MAGIC = 0xEF


#####################
#       Enums       #
#####################
class ESPChip(Enum):
    """
    ESP chip type, keyed by the `chip_id` field of the extended header (the same
    `IMAGE_CHIP_ID` values esptool uses). `ESP8266` is a sentinel for images
    without an extended header (and therefore no chip id).
    """

    ESP8266 = -1
    ESP32 = 0x0000
    ESP32S2 = 0x0002
    ESP32C3 = 0x0005
    ESP32S3 = 0x0009
    ESP32C2 = 0x000C
    ESP32C6 = 0x000D
    ESP32H2 = 0x0010
    ESP32P4 = 0x0012
    ESP32C5 = 0x0017
    UNKNOWN = 0xFFFF

    @classmethod
    def from_chip_id(cls, chip_id: int) -> "ESPChip":
        try:
            return cls(chip_id)
        except ValueError:
            return cls.UNKNOWN


class ESPAppFlashMode(Enum):
    QIO = 0
    QOUT = 1
    DIO = 2
    DOUT = 3


# Specific Flash Size Enums for each chip type
class FlashSizeESP8266(IntEnum):
    S_512KB = 0x00
    S_256KB = 0x10
    S_1MB = 0x20
    S_2MB = 0x30
    S_4MB = 0x40
    S_2MB_C1 = 0x50
    S_4MB_C1 = 0x60
    S_8MB = 0x80
    S_16MB = 0x90


class FlashSizeESP32(IntEnum):
    S_1MB = 0x00
    S_2MB = 0x10
    S_4MB = 0x20
    S_8MB = 0x30
    S_16MB = 0x40


class FlashSizeESP32S2S3(IntEnum):
    S_1MB = 0x00
    S_2MB = 0x10
    S_4MB = 0x20
    S_8MB = 0x30
    S_16MB = 0x40
    S_32MB = 0x50
    S_64MB = 0x60
    S_128MB = 0x70


class FlashFrequencyESP8266(IntEnum):
    F_40MHz = 0
    F_26MHz = 1
    F_20MHz = 2
    F_80MHz = 0xF


class FlashFrequencyESP32(IntEnum):
    ITFF_0MHz = 0
    ITFF_1MHz = 1
    ITFF_2MHz = 2
    ITFF_FMHz = 0xF


class FlashFrequencyESP32C6(IntEnum):
    F_80MHz = 0
    F_20MHz = 2


class FlashSize:
    @staticmethod
    def from_value(value: int, chip: Optional[ESPChip] = None) -> IntEnum:
        if chip is ESPChip.ESP8266:
            return FlashSizeESP8266(value)
        elif chip in (ESPChip.ESP32S2, ESPChip.ESP32S3):
            return FlashSizeESP32S2S3(value)
        return FlashSizeESP32(value)


class FlashFrequency:
    @staticmethod
    def from_value(value: int, chip: Optional[ESPChip] = None) -> IntEnum:
        if chip is ESPChip.ESP8266:
            return FlashFrequencyESP8266(value)
        elif chip is ESPChip.ESP32C6:
            return FlashFrequencyESP32C6(value)
        return FlashFrequencyESP32(value)


######################
# UNPACKER RESOURCES #
######################
@dataclass
class ESPAppSection(NamedProgramSection):
    """
    A loadable segment of an ESP app image.

    The only semantically meaningful children of an `ESPApp`: each corresponds to one
    firmware segment that is loaded to `virtual_address`. Header, checksum, hash, and other
    metadata are exposed as `ESPAppAttributes` rather than as child resources.

    :ivar virtual_address: The address the segment is loaded to
    :ivar size: The size of the segment in bytes
    :ivar name: The memory-type name of the segment (e.g. "DROM", "IRAM")
    :ivar section_index: Index of the segment within the image (0-based)
    """

    section_index: int

    @index
    def SectionIndex(self) -> int:
        return self.section_index


@dataclass
class ESPApp(Program):
    """
    App image for ESP chips.
    """

    async def get_sections(self) -> Iterable[ESPAppSection]:
        """
        Return the children `ESPAppSection` resources.

        :return: An iterable of `ESPAppSection` instances
        """
        return await self.resource.get_children_as_view(
            ESPAppSection,
            ResourceFilter(
                tags=(ESPAppSection,),
            ),
        )

    async def get_section_by_name(self, name: str) -> ESPAppSection:
        """
        Get a specific `ESPAppSection` by its name.

        :param name: The name of the section to retrieve
        :raises NotFoundError: If no section with the given name is found
        :return: The `ESPAppSection` instance with the specified name
        """
        return await self.resource.get_only_child_as_view(
            ESPAppSection,
            ResourceFilter(
                tags=(ESPAppSection,),
                attribute_filters=(ResourceAttributeValueFilter(ESPAppSection.SectionName, name),),
            ),
        )


######################
# ANALYZER RESOURCES #
######################
@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ESPAppAttributes(ResourceAttributes):
    """
    Metadata parsed from an ESP app image, attached to the `ESPApp` resource.

    The header, extended header, checksum and SHA256 digest are recorded here as attributes
    rather than as tagged child resources (only loadable segments get child resources).
    Extended-header and hash fields are only populated for ESP32-family images (ESP8266 images
    have neither), and are otherwise left at their defaults.
    """

    magic: int
    num_segments: int
    flash_mode: int
    flash_size: int
    flash_frequency: int
    entry_point: int
    chip: ESPChip
    checksum: int
    calculated_checksum: int
    checksum_valid: bool
    has_extended_header: bool
    hash_appended: bool
    hash_valid: bool
    chip_id: Optional[int] = None
    min_chip_rev_deprecated: Optional[int] = None
    min_chip_rev: Optional[int] = None
    max_chip_rev: Optional[int] = None
    wp_pin: Optional[int] = None
    clk_drv: Optional[int] = None
    q_drv: Optional[int] = None
    d_drv: Optional[int] = None
    cs_drv: Optional[int] = None
    hd_drv: Optional[int] = None
    wp_drv: Optional[int] = None
    stored_hash: Optional[bytes] = None
    calculated_hash: Optional[bytes] = None


######################
# MODIFIER RESOURCES #
######################
@dataclass
class ESPAppHeaderModifierConfig(ComponentConfig):
    """
    Configuration for editing the 8-byte ESP app header in place. Any field left `None` is
    left unchanged.
    """

    flash_mode: Optional[ESPAppFlashMode] = None
    flash_size: Optional[int] = None
    flash_frequency: Optional[int] = None
    entry_point: Optional[int] = None
