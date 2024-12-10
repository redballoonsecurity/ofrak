import logging
import os
import tempfile
from dataclasses import dataclass
from enum import Enum
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
from .esp_flash import ESPFlashSection

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


#####################
#     RESOURCES     #
#####################
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
    flash_size: int
    flash_frequency: int
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


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ESPAppAttributes(ResourceAttributes):
    chip_name: str
    checksum_valid: bool
    calculated_checksum: int
    hash_valid: bool
    calculated_hash: int


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


@dataclass
class ESPAppConfig(ComponentConfig):
    f: NamedTemporaryFile
    offset: int
    magic: bytes
    chip: str
    image: ESP8266V2FirmwareImage


def determine_chip(f: NamedTemporaryFile) -> str:
    """
    Determines the chip type based on the firmware image.

    :param f: A temporary file object containing the firmware image
    :return: The chip name as a string, defaults to 'esp8266' if not determined
    """
    extended_header = f.read(16)
    if extended_header[-1] not in [0, 1]:
        return "esp8266"

    chip_id = int.from_bytes(extended_header[4:5], "little")
    for rom in [n for n in ROM_LIST if n.CHIP_NAME != "ESP8266"]:
        if chip_id == rom.IMAGE_CHIP_ID:
            return rom.CHIP_NAME.lower()
    return "esp8266"


def check_magic(f: NamedTemporaryFile):
    """
    Checks the magic number of the firmware image to verify its validity.

    :param f: A temporary file object containing the firmware image
    :return: The magic number as an integer
    :raises UnpackerError: If the file is empty or the magic number is invalid
    """
    try:
        common_header = f.read(8)
        magic = common_header[0]
    except IndexError:
        raise UnpackerError("File is empty")
    if magic not in [
        ESPLoader.ESP_IMAGE_MAGIC,
        ESP8266V2FirmwareImage.IMAGE_V2_MAGIC,
    ]:
        raise UnpackerError(
            "This is not a valid image " "(invalid magic number: {:#x})".format(magic)
        )
    return magic


async def get_esp_app(resource: Resource, config: Optional[ESPAppConfig]):
    if config:
        return config
    else:
        f = NamedTemporaryFile()
        data = await resource.get_data()
        offset = data.find(b"\xE9")
        if offset > -1:
            f.write(data[offset:])
            f.flush()
            f.seek(0)
        else:
            raise UnpackerError("This is not a valid ESP image " "(could not find magic number)")
        magic = check_magic(f)
        chip = determine_chip(f)
        image = LoadFirmwareImage(chip, f.name)
    return ESPAppConfig(f, offset, magic, chip, image)


####################
#    IDENTIFIER    #
####################
class ESPAppIdentifier(Identifier):
    """
    Identify ESP apps.

    :param targets: A tuple containing the target resource types for identification
    """

    targets = (File, GenericBinary, Program, ESPFlashSection)

    async def identify(self, resource: Resource, config=None) -> None:
        """
        Identifies if the given resource is an ESP app.

        :param resource: The resource to identify
        :param config: Optional configuration for identification
        """
        data = await resource.get_data(range=Range(0, 8))
        magicByte_check = data[0] == ESP_APP_MAGIC or data[0] == ESP8266V2_APP_MAGIC
        flashmode_check = data[2] in {0, 1, 2, 3}
        lower_byte_three_check = (data[3] & 0xF) in {0, 1, 2, 0xF}
        if magicByte_check and flashmode_check and lower_byte_three_check:
            resource.add_tag(ESPApp)


####################
#    UNPACKER      #
####################
class ESPAppUnpacker(Unpacker[None]):
    """
    Unpacker for ESP apps, supporting both ESP8266 and ESP32 chips. It extracts
    various headers, sections, and metadata from the firmware binary.

    :param id: Identifier for the unpacker
    :param targets: A tuple containing the target resource types for unpacking
    :param children: A tuple containing the children resource types expected
        after unpacking
    """

    id = b"ESP32AppUnpacker"
    targets = (ESPApp,)
    children = (
        ESPAppHeader,
        ESPAppExtendedHeader,
        ESPAppChecksum,
        ESPAppHash,
        ESPAppSignature,
        ESPAppSection,
        ESPAppSectionHeader,
        ESPAppDescription,
        ESPBootloaderDescription,
    )

    async def unpack(self, resource: Resource, config: Optional[ESPAppConfig]):
        """
        Asynchronously unpacks an ESP app, extracting its components and metadata.

        :param resource: The resource to unpack
        :param config: Optional configuration for unpacking
        :raises UnpackerError: If unpacking fails due to invalid data or file operations
        """
        config = await get_esp_app(resource, config)
        try:
            resource.add_attributes(await resource.analyze(ESPAppAttributes))
            flash_s_bits, flash_fr_bits = self.__parse_flash_bits(config.image)

            header = ESPAppHeader(
                magic=config.magic,
                num_segments=len(config.image.segments),
                flash_mode=ESPAppFlashMode(config.image.flash_mode),
                flash_size=flash_s_bits,
                flash_frequency=flash_fr_bits,
                entry_point=config.image.entrypoint,
            )
            await resource.create_child_from_view(
                header, data_range=Range(0, ESP_APP_HEADER_SIZE).translate(config.offset)
            )
            if config.chip != "esp8266":
                extended_header = ESPAppExtendedHeader(
                    wp_pin=config.image.wp_pin,
                    clk_drv=config.image.clk_drv,
                    q_drv=config.image.q_drv,
                    d_drv=config.image.d_drv,
                    cs_drv=config.image.cs_drv,
                    hd_drv=config.image.hd_drv,
                    wp_drv=config.image.wp_drv,
                    chip_id=config.image.chip_id,
                    min_chip_rev_deprecated=config.image.min_rev,
                    min_chip_rev=config.image.min_rev_full,
                    max_chip_rev=config.image.max_rev_full,
                    hash_appended=config.image.append_digest,
                )
                await resource.create_child_from_view(
                    extended_header,
                    data_range=Range.from_size(
                        ESP_APP_HEADER_SIZE, ESP_APP_EXTENDED_HEADER_SIZE
                    ).translate(config.offset),
                )

            # Segments overview
            app_desc = None
            bootloader_desc = None
            for idx, seg in enumerate(config.image.segments, start=1):
                segs = seg.get_memory_type(config.image)
                seg_name = ", ".join(segs)
                if "DROM" in segs:  # The DROM segment starts with the esp_app_desc_t struct
                    app_desc = seg.data[:256]
                elif "DRAM" in segs:
                    # The DRAM segment starts with the esp_bootloader_desc_t struct
                    if len(seg.data) >= 80:
                        bootloader_desc = seg.data[:80]
                section_header = ESPAppSectionHeader(
                    section_index=idx,
                    name=seg_name,
                    memory_offset=seg.addr,
                    segment_size=len(seg.data),
                )
                await resource.create_child_from_view(
                    section_header,
                    data_range=Range.from_size(
                        (seg.file_offs - ESP_APP_SEGMENT_HEADER_SIZE),
                        ESP_APP_SEGMENT_HEADER_SIZE,
                    ).translate(config.offset),
                )
                section = ESPAppSection(
                    section_index=idx,
                    name=section_header.name,
                    virtual_address=section_header.memory_offset,
                    size=section_header.segment_size,
                )
                section_range = (
                    Range.from_size(seg.file_offs, len(seg.data)) if len(seg.data) > 0 else None
                )
                section_range.translate(config.offset)
                section_r = await resource.create_child_from_view(section, data_range=section_range)

                if "IRAM" in seg_name or "IROM" in seg_name:
                    section_r.add_tag(CodeRegion)

            # Footer
            # Sectors (including the last one) are aligned to leave space for the next header.
            checksum_offset = seg.file_offs + ESP_APP_SEGMENT_HEADER_SIZE + len(seg.data)
            checksum_offset = (
                (checksum_offset + 16) // 16 * 16
            ) - 1  # Align to next 16-byte boundary
            await resource.create_child_from_view(
                ESPAppChecksum(checksum=config.image.checksum),
                data_range=Range.from_size(checksum_offset, 1).translate(config.offset),
            )
            if config.image.append_digest:
                hash = ESPAppHash(hash=config.image.stored_digest)
                hash_offset = checksum_offset + 1
                await resource.create_child_from_view(
                    hash, data_range=Range.from_size(hash_offset, 32).translate(config.offset)
                )
                if config.image.secure_pad == "1":
                    # Version + signature + 12 trailing bytes due to alignment = 80 bytes
                    config.f.seek(-80, os.SEEK_END)
                    signature = ESPAppSignature(
                        version=struct.unpack("<I", config.f.read(4))[0],
                        signature=config.f.read(64),
                    )
                    signature_offset = hash_offset + 32
                    await resource.create_child_from_view(
                        signature, data_range=Range.from_size(signature_offset, 80).translate(config.offset)
                    )

                elif config.image.secure_pad == "2":  # Secure Boot V2
                    # TODO: ESPTool.py comment says: "after checksum: SHA-256 digest +
                    # signature sector, but we place signature sector after the 64KB
                    # boundary" so this might work but unsure
                    config.f.seek(-64004, os.SEEK_END)
                    signature = ESPAppSignature(
                        version=struct.unpack("<I", config.f.read(4))[0],
                        signature=config.f.read(64000),
                    )
                    signature_offset = hash_offset + 32
                    await resource.create_child_from_view(
                        signature, data_range=Range.from_size(signature_offset, 64004).translate(config.offset)
                    )
            # Process application description if present
            if app_desc:
                app_description, magic_word = self.__parse_app_description(app_desc)
                if magic_word == 0xABCD5432:
                    await resource.create_child_from_view(
                        app_description,
                        data_range=Range.from_size(
                            ESP_APP_HEADER_SIZE + ESP_APP_EXTENDED_HEADER_SIZE + ESP_APP_SEGMENT_HEADER_SIZE,
                            256,
                        ).translate(config.offset),
                    )
            elif bootloader_desc:
                bootloader_description, magic_byte = self.__parse_bootloader_description(
                    bootloader_desc
                )
                if magic_byte == 80:
                    await resource.create_child_from_view(
                        bootloader_description,
                        data_range=Range.from_size(
                            ESP_APP_HEADER_SIZE + ESP_APP_EXTENDED_HEADER_SIZE + ESP_APP_SEGMENT_HEADER_SIZE, 80
                        ).translate(config.offset),
                    )
        finally:
            if hasattr(config, "f"):
                config.f.close()

    def __parse_flash_bits(self, image) -> Tuple[int, int]:
        """
        Extracts and returns flash size and frequency bits from the firmware image.

        :param image: The firmware image object
        :return: A tuple containing the flash size bits and flash frequency bits
        """
        flash_s_bits = image.flash_size_freq & 0xF0
        flash_fr_bits = image.flash_size_freq & 0x0F
        return flash_s_bits, flash_fr_bits

    def __parse_app_description(self, app_desc: bytes) -> ESPAppDescription:
        """
        Parses and returns the application description from segment data.

        :param app_desc: The application description data extracted from the DROM segment
        :return: An ESPAppDescription object populated with the parsed data
        """
        APP_DESC_STRUCT_FMT = "<II8s32s32s16s16s32s32s80s"
        unpacked_data = struct.unpack(APP_DESC_STRUCT_FMT, app_desc)
        return (
            ESPAppDescription(
                magic=unpacked_data[0],
                secure_version=unpacked_data[1],
                reserv1=unpacked_data[2],
                version=unpacked_data[3],
                project_name=unpacked_data[4],
                time=unpacked_data[5],
                date=unpacked_data[6],
                idf_ver=unpacked_data[7],
                app_eld_sha256=unpacked_data[8],
                reserv2=unpacked_data[9],
            ),
            unpacked_data[0],
        )

    def __parse_bootloader_description(self, bootloader_desc: bytes) -> ESPBootloaderDescription:
        """
        Parses and returns the bootloader description from segment data.

        :param bootloader_desc: The bootloader description data extracted from the DRAM segment
        :return: An ESPBootloaderDescription object populated with the parsed data
        """
        BOOTLOADER_DESC_STRUCT_FMT = "<B3sI32s24s16s"
        unpacked_data = struct.unpack(BOOTLOADER_DESC_STRUCT_FMT, bootloader_desc)
        return (
            ESPBootloaderDescription(
                magic=unpacked_data[0],
                reserved=unpacked_data[1],
                version=unpacked_data[2],
                idf_ver=unpacked_data[3],
                date_time=unpacked_data[4],
                reserved2=unpacked_data[5],
            ),
            unpacked_data[0],
        )


####################
#    Analyzer     #
####################
class ESPAppAnalyzer(Analyzer[None, ESPAppAttributes]):
    """
    Analyze attributes of ESP app.
    """

    targets = (ESPApp,)
    outputs = (ESPAppAttributes,)

    async def analyze(self, resource: Resource, config: Optional[ESPAppConfig]) -> ESPAppAttributes:
        config = await get_esp_app(resource, config)
        try:
            calculated_checksum = int(config.image.calculate_checksum())
            checksum_valid = True if config.image.checksum == calculated_checksum else False
            hash_valid = "Not Available"
            calculated_hash = "Not Available"
            if config.image.append_digest:
                calculated_hash = config.image.calc_digest.hex()
                if config.image.stored_digest == config.image.calc_digest:
                    hash_valid = True
                else:
                    hash_valid = False

            return ESPAppAttributes(
                chip_name=self.__get_chip_name(config.image),
                checksum_valid=checksum_valid,
                calculated_checksum=calculated_checksum,
                hash_valid=hash_valid,
                calculated_hash=calculated_hash,
            )
        finally:
            if hasattr(config, "f"):
                config.f.close()

    def __get_chip_name(self, image):
        for c in CHIP_DEFS.values():
            if getattr(c, "IMAGE_CHIP_ID", None) == image.chip_id:
                return c.CHIP_NAME
        return "Unknown ID"
