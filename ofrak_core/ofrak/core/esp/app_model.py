import logging
import os
import tempfile
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Iterable, Tuple, Optional
from io import BytesIO
import struct

from ofrak.core.program import Program, CodeRegion
from ofrak.core.program_section import NamedProgramSection
from ofrak.model.resource_model import index, ResourceAttributes
from ofrak.component.identifier import Identifier
from ofrak.component.analyzer import Analyzer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import (
    ResourceAttributeValueFilter,
    ResourceFilter,
)
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.range import Range
from ofrak.model.component_model import ComponentConfig

from esptool import CHIP_DEFS, ESPLoader
from esptool.bin_image import LoadFirmwareImage, ESP8266V2FirmwareImage
from esptool.targets import ROM_LIST

from tempfile import NamedTemporaryFile, _TemporaryFileWrapper
from .flash import ESPFlashSection

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

#### ESP32S2 or ESP32S3:
    +--------+------------------------------------------------------------------+
    | Byte   | Description                                                      |
    +========+==================================================================+
    | 0      | Magic number (0xE9)                                              |
    +--------+------------------------------------------------------------------+
    | 1      | Number of segments                                               |
    +--------+------------------------------------------------------------------+
    | 2      | SPI Flash Mode (0 = QIO, 1 = QOUT, 2 = DIO, 3 = DOUT)            |
    +--------+------------------------------------------------------------------+
    | 3      | High four bits - Flash size (0 = 1MB, 1 = 2MB, 2 = 4MB, 3 = 8MB, |
    |        |                              4=16MB,5=32MB,6=64MB,7=128MB")      |
    |        | Low four bits - Flash frequency (0 = ITFF_0MHz, 1 = ITFF_1MHz,   |
    |        |                                  2 = ITFF_2MHz, 0xf = ITFF_FMHz) |
    +--------+------------------------------------------------------------------+
    | 4-7    | Entry point address                                              |
    +--------+------------------------------------------------------------------+


#### ESP32C6:
    +--------+------------------------------------------------------------------+
    | Byte   | Description                                                      |
    +========+==================================================================+
    | 0      | Magic number (0xE9)                                              |
    +--------+------------------------------------------------------------------+
    | 1      | Number of segments                                               |
    +--------+------------------------------------------------------------------+
    | 2      | SPI Flash Mode (0 = QIO, 1 = QOUT, 2 = DIO, 3 = DOUT)            |
    +--------+------------------------------------------------------------------+
    | 3      | High four bits - Flash size (0 = 1MB, 1 = 2MB, 2 = 4MB, 3 = 8MB, |
    |        |                              4 = 16MB)                           |
    |        | Low four bits - Flash frequency (0 = 80MHz, 0 = 40MHz, 2 = 20MHz)|
    +--------+------------------------------------------------------------------+
    | 4-7    | Entry point address                                              |
    +--------+------------------------------------------------------------------+

    Note: Frequency 0 can means 80MHz or 40MHz based on MSPI clock source mode.

#### IF NONE OF THE ABOVE:
    +--------+------------------------------------------------------------------+
    | Byte   | Description                                                      |
    +========+==================================================================+
    | 0      | Magic number (0xE9)                                              |
    +--------+------------------------------------------------------------------+
    | 1      | Number of segments                                               |
    +--------+------------------------------------------------------------------+
    | 2      | SPI Flash Mode (0 = QIO, 1 = QOUT, 2 = DIO, 3 = DOUT)            |
    +--------+------------------------------------------------------------------+
    | 3      | High four bits - Flash size (0 = 1MB, 1 = 2MB, 2 = 4MB, 3 = 8MB, |
    |        |                              4 = 16MB)                           |
    |        | Low four bits - Flash frequency (0 = ITFF_0MHz, 1 = ITFF_1MHz,   |
    |        |                                  2 = ITFF_3MHz, 0xf = ITFF_FMHz) |
    +--------+------------------------------------------------------------------+
    | 4-7    | Entry point address                                              |
    +--------+------------------------------------------------------------------+

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
    digest “simple hash” (of the entire image) is appended after the checksum.
    This digest is separate to secure boot and only used for detecting
    corruption. The SPI flash info cannot be changed during flashing if hash is
    appended after the image.

    If secure boot is enabled, a signature is also appended (and the simple hash
    is included in the signed data). This image signature is `Secure Boot V1
    <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v1.html#image-signing-algorithm>`_
    and `Secure Boot V2
    <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v2.html#signature-block-format>`_
    specific.

## Analyzing a Binary Image
To analyze a binary image and get a complete summary of its headers and
segments, use the :ref:`image_info <image-info>` command with the ``--version
2`` option.
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
    F_80MHz = 0xf

class FlashFrequencyESP32(IntEnum):
    ITFF_0MHz = 0
    ITFF_1MHz = 1
    ITFF_2MHz = 2
    ITFF_FMHz = 0xf

class FlashFrequencyESP32C6(IntEnum):
    F_80MHz = 0
    F_40MHz = 0  # Note: Frequency 0 can mean either 80MHz or 40MHz based on MSPI clock source mode.
    F_20MHz = 2

class FlashSize:
    @staticmethod
    def from_value(value: int, chip_type: Optional[str] = None):
        if chip_type:
            if chip_type == ROM_LIST[0].CHIP_NAME.lower():
                return FlashSizeESP8266(value)
            elif chip_type.lower().endswith("s2") or chip_type.lower().endswith("s3"):
                return FlashSizeESP32S2S3(value)
        return FlashSizeESP32(value)

class FlashFrequency:
    @staticmethod
    def from_value(value: int, chip_type: Optional[str] = None):
        if chip_type:
            if chip_type == ROM_LIST[0].CHIP_NAME.lower():
                return FlashFrequencyESP8266(value)
            elif chip_type.lower().endswith("c6"):
                return FlashFrequencyESP32C6(value)
        return FlashFrequencyESP32(value)
        
######################
# UNPACKER RESOURCES #
######################
@dataclass
class ESPAppHeader(ResourceView):
    """
    ESP app header.

    :param magic: Magic number indicating the start of the header
    :param num_segments: Number of segments in the binary
    :param flash_mode: Flash mode used by the ESP
    :param flash_size: Size of the flash
    :param flash_frequency: Frequency of the flash
    :param entry_point: Entry point address for execution
    """

    magic: int
    num_segments: int
    flash_mode: ESPAppFlashMode
    flash_size: IntEnum
    flash_frequency: IntEnum
    entry_point: int


@dataclass
class ESPAppExtendedHeader(ResourceView):
    """
    ESP app extended header.

    Describes additional configuration parameters not included in the basic header.

    :param wp_pin: Write protection pin setting
    :param clk_drv: Clock driver strength
    :param q_drv: Q driver strength
    :param d_drv: D driver strength
    :param cs_drv: CS driver strength
    :param hd_drv: HD driver strength
    :param wp_drv: WP driver strength
    :param chip_id: Chip ID for identification
    :param min_chip_rev_deprecated: Deprecated minimum chip revision
    :param min_chip_rev: Minimum chip revision supported
    :param max_chip_rev: Maximum chip revision supported
    :param hash_appended: Indicates if a hash is appended to the binary
    """

    wp_pin: int
    clk_drv: int
    q_drv: int
    d_drv: int
    cs_drv: int
    hd_drv: int
    wp_drv: int
    chip_id: int
    min_chip_rev_deprecated: int
    min_chip_rev: int
    max_chip_rev: int
    hash_appended: bool


@dataclass
class ESPAppDescription(ResourceView):
    """
    ESP App Description.

    Provides metadata about the application binary.

    :param magic: Magic word indicating the start of the app description
    :param secure_version: Secure version number
    :param reserv1: Reserved bytes
    :param version: Application version
    :param project_name: Name of the project
    :param time: Time of the build
    :param date: Date of the build
    :param idf_ver: IDF version used for building
    :param app_eld_sha256: SHA-256 hash of the app
    :param reserv2: Additional reserved bytes
    """

    magic: int
    secure_version: int
    reserv1: bytes
    version: bytes
    project_name: bytes
    time: bytes
    date: bytes
    idf_ver: bytes
    app_eld_sha256: bytes
    reserv2: bytes


@dataclass
class ESPBootloaderDescription(ResourceView):
    """
    ESP Bootloader Description.

    Contains metadata specific to the bootloader.

    :param magic: Magic byte indicating the start of the bootloader description
    :param reserved: Reserved bytes
    :param version: Bootloader version
    :param idf_ver: IDF version used for the bootloader
    :param date_time: Build date and time of the bootloader
    :param reserved2: Additional reserved bytes
    """

    magic: bytes
    reserved: bytes
    version: int
    idf_ver: bytes
    date_time: bytes
    reserved2: bytes


@dataclass
class ESPAppChecksum(ResourceView):
    """
    ESP app checksum.

    :param checksum: Checksum value
    """

    checksum: int


@dataclass
class ESPAppHash(ResourceView):
    """
    ESP app hash.

    :param hash: Hash value
    """

    hash: bytes


@dataclass
class ESPAppSignature(ResourceView):
    """
    ESP app Signature.

    :param version: Version of the signature
    :param signature: Signature bytes
    """

    version: int
    signature: bytes


@dataclass
class ESPAppSectionStructure(ResourceView):
    """
    Base class for section headers and sections, linking them via index.

    :param section_index: Index of the section
    """

    section_index: int

    @index
    def SectionIndex(self) -> int:
        """
        Returns the index of the section.

        :return: Index of the section
        """
        return self.section_index


@dataclass
class ESPAppSection(ESPAppSectionStructure, NamedProgramSection):
    """
    ESP app section.

    Represents a section within the ESP app.
    """

    async def get_header(self) -> "ESPAppSectionHeader":
        """
        Retrieves the header for this section.

        :return: The header of the section
        """
        return await self.resource.get_only_sibling_as_view(
            ESPAppSectionHeader,
            ResourceFilter(
                tags=(ESPAppSectionHeader,),
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        ESPAppSectionStructure.SectionIndex, self.section_index
                    )
                ],
            ),
        )


@dataclass
class ESPAppSectionHeader(ESPAppSectionStructure):
    """
    ESP app section header.

    Represents the header for a section within the ESP binary.

    :param name: Name of the section
    :param memory_offset: Memory offset for the section
    :param segment_size: Size of the section segment
    """

    name: str
    memory_offset: int
    segment_size: int

    async def get_body(self) -> "ESPAppSection":
        """
        Retrieves the body of the section.

        :return: The body of the section
        """
        return await self.resource.get_only_sibling_as_view(
            ESPAppSection,
            ResourceFilter(
                tags=(ESPAppSection,),
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        ESPAppSectionStructure.SectionIndex, self.section_index
                    )
                ],
            ),
        )

@dataclass
class ESPApp(Program):
    """
    App file for ESP chips.
    """

    async def get_sections(self) -> Iterable[ESPAppSection]:
        """
        Return the children `ESPSection` resources.

        :return: An iterable of `ESPSection` instances
        """
        return await self.resource.get_children_as_view(
            ESPAppSection,
            ResourceFilter(
                tags=(ESPAppSection,),
            ),
        )

    async def get_section_by_name(self, name: str) -> ESPAppSection:
        """
        Get a specific `ESPSection` by its name.

        :param name: The name of the section to retrieve
        :raises NotFoundError: If no section with the given name is found
        :return: The `ESPSection` instance with the specified name
        """
        await self.get_sections()

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
    chip_name: str
    checksum_valid: bool
    calculated_checksum: int
    hash_valid: bool
    calculated_hash: int

@dataclass
class ESPAppConfig(ComponentConfig):
    f: NamedTemporaryFile
    offset: int
    magic: bytes
    chip: str
    image: ESP8266V2FirmwareImage


######################
# MODIFIER RESOURCES #
######################
@dataclass
class ESPAppHeaderModifierConfig(ResourceView):
    flash_mode: Optional[ESPAppFlashMode] = None
    flash_size: Optional[int] = None
    flash_frequency: Optional[int] = None
    entry_point: Optional[int] = None

@dataclass
class ESPAppExtendedHeaderModifierConfig(ResourceView):
    wp_pin: Optional[int] = None
    clk_drv: Optional[int] = None
    q_drv: Optional[int] = None
    d_drv: Optional[int] = None
    cs_drv: Optional[int] = None
    hd_drv: Optional[int] = None
    wp_drv: Optional[int] = None
    chip_id: Optional[int] = None
    min_chip_rev_deprecated: Optional[int] = None
    min_chip_rev: Optional[int] = None
    max_chip_rev: Optional[int] = None
    hash_appended: Optional[bool] = None

@dataclass
class ESPAppDescriptionModifierConfig(ResourceView):
    secure_version: Optional[int] = None
    reserv1: Optional[bytes] = None
    version: Optional[bytes] = None
    project_name: Optional[bytes] = None
    time: Optional[bytes] = None
    date: Optional[bytes] = None
    idf_ver: Optional[bytes] = None
    app_eld_sha256: Optional[bytes] = None
    reserv2: Optional[bytes] = None

@dataclass
class ESPBootloaderDescriptionModifierConfig(ResourceView):
    reserved: Optional[bytes] = None
    version: Optional[int] = None
    idf_ver: Optional[bytes] = None
    date_time: Optional[bytes] = None
    reserved2: Optional[bytes] = None