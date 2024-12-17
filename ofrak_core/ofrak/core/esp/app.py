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
from ofrak.component.modifier import Modifier
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
from ofrak.core.esp.flash_model import ESPFlashSection

from ofrak.core.esp.app_model import *


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
        #TODO Looks like an identifier function why not in identifier?
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
            #TODO can this be removed?
            resource.add_attributes(await resource.analyze(ESPAppAttributes))
            flash_s_bits, flash_fr_bits = self.__parse_flash_bits(config.image)

            header = ESPAppHeader(
                magic=config.magic,
                num_segments=len(config.image.segments),
                flash_mode=ESPAppFlashMode(config.image.flash_mode),
                flash_size=FlashSize.from_value(flash_s_bits, config.chip),
                flash_frequency=FlashFrequency.from_value(flash_fr_bits),
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
#    ANALYZERS     #
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


####################
#     MODIFERS     #
####################
class ESPAppModifier(Modifier[None]):
    """
    Modify ESP app.
    """

    targets = (ESPApp,)

    async def modify(self, resource: Resource, config: Optional[ESPAppConfig]) -> None:
        config = await get_esp_app(resource, config)
        try:
            await resource.analyze(ESPAppAttributes)
        finally:
            if hasattr(config, "f"):
                config.f.close()