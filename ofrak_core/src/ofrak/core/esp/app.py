import hashlib
import struct
from typing import List

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.modifier import Modifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.core.program import CodeRegion
from ofrak.resource import Resource
from ofrak_type.range import Range

from ofrak.core.esp.flash_model import ESPFlashSection
from ofrak.core.esp.app_model import (
    ESPApp,
    ESPAppAttributes,
    ESPAppHeaderModifierConfig,
    ESPAppSection,
    ESPChip,
    ESP_APP_CHECKSUM_MAGIC,
    ESP_APP_EXTENDED_HEADER_SIZE,
    ESP_APP_HEADER_SIZE,
    ESP_APP_MAGIC,
    ESP_APP_SEGMENT_HEADER_SIZE,
    ESP8266V2_APP_MAGIC,
)

# Per-chip memory maps, mirroring esptool's ``ROM_LOADER.MEMORY_MAP``. A segment's memory type is
# determined by the region its load address falls into (this is how esptool names segments). These
# are baked in so the component has no runtime dependency on esptool.
_ESP_MEMORY_MAP = {
    ESPChip.ESP8266: (
        (0x3FF00000, 0x3FF00010, "DPORT"),
        (0x3FFE8000, 0x40000000, "DRAM"),
        (0x40100000, 0x40108000, "IRAM"),
        (0x40201010, 0x402E1010, "IROM"),
    ),
    ESPChip.ESP32: (
        (0x3F400000, 0x3F800000, "DROM"),
        (0x3F800000, 0x3FC00000, "EXTRAM_DATA"),
        (0x3FFAE000, 0x40000000, "DRAM"),
        (0x40000000, 0x40070000, "IROM"),
        (0x40070000, 0x40078000, "CACHE_PRO"),
        (0x40078000, 0x40080000, "CACHE_APP"),
        (0x40080000, 0x400A0000, "IRAM"),
        (0x400A0000, 0x400BFFFC, "DIRAM_IRAM"),
        (0x400C0000, 0x400C2000, "RTC_IRAM"),
        (0x400D0000, 0x40400000, "IROM"),
        (0x50000000, 0x50002000, "RTC_DATA"),
    ),
    ESPChip.ESP32S2: (
        (0x3F000000, 0x3FF80000, "DROM"),
        (0x3FFB0000, 0x40000000, "DRAM"),
        (0x40020000, 0x40070000, "IRAM"),
        (0x40070000, 0x40072000, "RTC_IRAM"),
        (0x40080000, 0x40800000, "IROM"),
        (0x50000000, 0x50002000, "RTC_DATA"),
    ),
    ESPChip.ESP32S3: (
        (0x3C000000, 0x3D000000, "DROM"),
        (0x3FC88000, 0x3FD00000, "DRAM"),
        (0x40370000, 0x403E0000, "IRAM"),
        (0x42000000, 0x42800000, "IROM"),
        (0x600FE000, 0x60100000, "RTC_IRAM"),
        (0x50000000, 0x50002000, "RTC_DATA"),
    ),
    ESPChip.ESP32C3: (
        (0x3C000000, 0x3C800000, "DROM"),
        (0x3FC80000, 0x3FCE0000, "DRAM"),
        (0x42000000, 0x42800000, "IROM"),
        (0x4037C000, 0x403E0000, "IRAM"),
        (0x50000000, 0x50002000, "RTC_IRAM"),
    ),
}


def _determine_chip(data: bytes) -> ESPChip:
    """
    Determine the ESP chip type by inspecting the (optional) extended header. ESP8266 images have
    no extended header, so an image is treated as ESP8266 unless the bytes where the extended
    header would be carry a plausible ``hash_appended`` flag (0/1) and a known chip id.

    :param data: the ESP app image bytes
    :return: the detected :class:`ESPChip` (``ESP8266`` when no extended header is present)
    """
    if len(data) < ESP_APP_HEADER_SIZE + ESP_APP_EXTENDED_HEADER_SIZE:
        return ESPChip.ESP8266
    if data[23] not in (0, 1):  # hash_appended flag (last byte of the extended header)
        return ESPChip.ESP8266
    chip = ESPChip.from_chip_id(data[12])  # chip id (low byte) within the extended header
    if chip is ESPChip.UNKNOWN:
        return ESPChip.ESP8266
    return chip


def _segment_memory_types(virtual_address: int, chip: ESPChip) -> List[str]:
    memory_map = _ESP_MEMORY_MAP.get(chip, ())
    return [name for start, end, name in memory_map if start <= virtual_address < end]


def _segment_name(virtual_address: int, chip: ESPChip, index: int) -> str:
    memory_types = _segment_memory_types(virtual_address, chip)
    return ", ".join(memory_types) if memory_types else f"segment_{index}"


def _is_code_segment(virtual_address: int, chip: ESPChip) -> bool:
    return any("IRAM" in t or "IROM" in t for t in _segment_memory_types(virtual_address, chip))


def _iter_segments(data: bytes, has_extended_header: bool, num_segments: int):
    """
    Yield ``(index, virtual_address, data_offset, size)`` for each segment, statelessly walking
    the segment table that follows the (extended) header.
    """
    offset = ESP_APP_HEADER_SIZE + (ESP_APP_EXTENDED_HEADER_SIZE if has_extended_header else 0)
    for index in range(num_segments):
        if offset + ESP_APP_SEGMENT_HEADER_SIZE > len(data):
            break
        virtual_address, size = struct.unpack_from("<II", data, offset)
        data_offset = offset + ESP_APP_SEGMENT_HEADER_SIZE
        if data_offset + size > len(data):
            break
        yield index, virtual_address, data_offset, size
        offset = data_offset + size


def _checksum_offset(end_of_segments: int) -> int:
    """The checksum is the last byte of the 16-byte-aligned block following the segments."""
    return ((end_of_segments + 16) // 16) * 16 - 1


####################
#    IDENTIFIER    #
####################
class ESPAppIdentifier(Identifier):
    """
    Identify ESP apps.

    :param targets: A tuple containing the target resource types for identification
    """

    targets = (GenericBinary, ESPFlashSection)

    async def identify(self, resource: Resource, config=None) -> None:
        """
        Identifies if the given resource is an ESP app.

        :param resource: The resource to identify
        :param config: Optional configuration for identification
        """
        data = await resource.get_data(range=Range(0, 8))
        if data:
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
    Unpacker for ESP apps (ESP8266 and the ESP32 family).

    Only the loadable segments are unpacked into child resources (`ESPAppSection`); the header,
    extended header, checksum, and SHA256 digest are exposed as `ESPAppAttributes` via
    `ESPAppAnalyzer` rather than as tagged children. Segments mapped to instruction memory
    (IRAM / IROM) are additionally tagged as `CodeRegion`.

    :param id: Identifier for the unpacker
    :param targets: A tuple containing the target resource types for unpacking
    :param children: A tuple containing the children resource types created when unpacking
    """

    id = b"ESP32AppUnpacker"
    targets = (ESPApp,)
    children = (ESPAppSection,)

    async def unpack(self, resource: Resource, config=None) -> None:
        data = bytes(await resource.get_data())
        if not data or data[0] not in (ESP_APP_MAGIC, ESP8266V2_APP_MAGIC):
            raise UnpackerError("This is not a valid ESP image (invalid or missing magic number).")

        chip = _determine_chip(data)
        has_extended_header = chip is not ESPChip.ESP8266
        num_segments = data[1]

        for index, virtual_address, data_offset, size in _iter_segments(
            data, has_extended_header, num_segments
        ):
            section = ESPAppSection(
                virtual_address=virtual_address,
                size=size,
                name=_segment_name(virtual_address, chip, index),
                section_index=index,
            )
            data_range = Range.from_size(data_offset, size) if size > 0 else None
            section_r = await resource.create_child_from_view(section, data_range=data_range)
            if _is_code_segment(virtual_address, chip):
                section_r.add_tag(CodeRegion)


####################
#    ANALYZER      #
####################
class ESPAppAnalyzer(Analyzer[None, ESPAppAttributes]):
    """
    Statelessly parse an ESP app's header, extended header, checksum, and SHA256 digest into
    `ESPAppAttributes`. The checksum (XOR of all segment bytes with `0xEF`) and digest (SHA256 of
    the image up to and including the checksum byte) are recomputed and compared against the
    stored values to report validity.
    """

    targets = (ESPApp,)
    outputs = (ESPAppAttributes,)

    async def analyze(self, resource: Resource, config=None) -> ESPAppAttributes:
        data = bytes(await resource.get_data())

        magic, num_segments, flash_mode, flash_size_freq = data[0], data[1], data[2], data[3]
        (entry_point,) = struct.unpack_from("<I", data, 4)

        chip = _determine_chip(data)
        has_extended_header = chip is not ESPChip.ESP8266

        chip_id = min_chip_rev_deprecated = min_chip_rev = max_chip_rev = None
        wp_pin = clk_drv = q_drv = d_drv = cs_drv = hd_drv = wp_drv = None
        hash_appended = False
        if has_extended_header:
            ext = data[ESP_APP_HEADER_SIZE : ESP_APP_HEADER_SIZE + ESP_APP_EXTENDED_HEADER_SIZE]
            wp_pin = ext[0]
            drive_settings = ext[1] | (ext[2] << 8) | (ext[3] << 16)
            clk_drv = (drive_settings >> 0) & 0x3
            q_drv = (drive_settings >> 2) & 0x3
            d_drv = (drive_settings >> 4) & 0x3
            cs_drv = (drive_settings >> 6) & 0x3
            hd_drv = (drive_settings >> 8) & 0x3
            wp_drv = (drive_settings >> 10) & 0x3
            chip_id, min_chip_rev_deprecated, min_chip_rev, max_chip_rev = struct.unpack_from(
                "<HBHH", ext, 4
            )
            hash_appended = ext[15] == 1

        # Walk the segments to find where the footer (checksum / hash) sits and to gather the
        # bytes the checksum is computed over.
        segment_bytes = bytearray()
        end_of_segments = ESP_APP_HEADER_SIZE + (
            ESP_APP_EXTENDED_HEADER_SIZE if has_extended_header else 0
        )
        for _index, _vaddr, data_offset, size in _iter_segments(
            data, has_extended_header, num_segments
        ):
            segment_bytes += data[data_offset : data_offset + size]
            end_of_segments = data_offset + size

        checksum_offset = _checksum_offset(end_of_segments)
        stored_checksum = data[checksum_offset] if checksum_offset < len(data) else 0
        calculated_checksum = ESP_APP_CHECKSUM_MAGIC
        for byte in segment_bytes:
            calculated_checksum ^= byte
        calculated_checksum &= 0xFF
        checksum_valid = stored_checksum == calculated_checksum

        stored_hash = calculated_hash = None
        hash_valid = False
        if hash_appended:
            hash_offset = checksum_offset + 1
            stored_hash = data[hash_offset : hash_offset + 32]
            calculated_hash = hashlib.sha256(data[:hash_offset]).digest()
            hash_valid = stored_hash == calculated_hash

        return ESPAppAttributes(
            magic=magic,
            num_segments=num_segments,
            flash_mode=flash_mode,
            flash_size=flash_size_freq & 0xF0,
            flash_frequency=flash_size_freq & 0x0F,
            entry_point=entry_point,
            chip=chip,
            checksum=stored_checksum,
            calculated_checksum=calculated_checksum,
            checksum_valid=checksum_valid,
            has_extended_header=has_extended_header,
            hash_appended=hash_appended,
            hash_valid=hash_valid,
            chip_id=chip_id,
            min_chip_rev_deprecated=min_chip_rev_deprecated,
            min_chip_rev=min_chip_rev,
            max_chip_rev=max_chip_rev,
            wp_pin=wp_pin,
            clk_drv=clk_drv,
            q_drv=q_drv,
            d_drv=d_drv,
            cs_drv=cs_drv,
            hd_drv=hd_drv,
            wp_drv=wp_drv,
            stored_hash=stored_hash,
            calculated_hash=calculated_hash,
        )


####################
#    MODIFIERS     #
####################
class ESPAppHeaderModifier(Modifier[ESPAppHeaderModifierConfig]):
    """
    Edit the 8-byte ESP app header in place (flash mode/size/frequency and entry point). Run
    `ESPAppPacker` afterwards to recompute the checksum and SHA256 digest for the modified image.
    """

    id = b"ESPAppHeaderModifier"
    targets = (ESPApp,)

    async def modify(self, resource: Resource, config: ESPAppHeaderModifierConfig) -> None:
        header = bytearray(await resource.get_data(range=Range(0, ESP_APP_HEADER_SIZE)))
        if config.flash_mode is not None:
            header[2] = config.flash_mode.value
        if config.flash_size is not None or config.flash_frequency is not None:
            size_bits = config.flash_size if config.flash_size is not None else (header[3] & 0xF0)
            freq_bits = (
                config.flash_frequency if config.flash_frequency is not None else (header[3] & 0x0F)
            )
            header[3] = (size_bits & 0xF0) | (freq_bits & 0x0F)
        if config.entry_point is not None:
            struct.pack_into("<I", header, 4, config.entry_point)
        resource.queue_patch(Range(0, ESP_APP_HEADER_SIZE), bytes(header))


####################
#      PACKER      #
####################
class ESPAppPacker(Packer[None]):
    """
    Packer for ESP apps that recomputes the checksum and SHA256 digest in place.

    Header / segment edits leave the trailing checksum byte and (for ESP32-family images) the
    appended SHA256 digest stale; this packer recalculates both so the repacked image is valid.
    """

    id = b"ESPAppPacker"
    targets = (ESPApp,)

    async def pack(self, resource: Resource, config=None) -> None:
        data = bytearray(await resource.get_data())
        chip = _determine_chip(data)
        has_extended_header = chip is not ESPChip.ESP8266
        num_segments = data[1]

        segment_bytes = bytearray()
        end_of_segments = ESP_APP_HEADER_SIZE + (
            ESP_APP_EXTENDED_HEADER_SIZE if has_extended_header else 0
        )
        for _index, _vaddr, data_offset, size in _iter_segments(
            data, has_extended_header, num_segments
        ):
            segment_bytes += data[data_offset : data_offset + size]
            end_of_segments = data_offset + size

        checksum_offset = _checksum_offset(end_of_segments)
        calculated_checksum = ESP_APP_CHECKSUM_MAGIC
        for byte in segment_bytes:
            calculated_checksum ^= byte
        calculated_checksum &= 0xFF
        if checksum_offset < len(data):
            data[checksum_offset] = calculated_checksum

        # Recompute the appended SHA256 digest (ESP32-family images with hash_appended set).
        hash_offset = checksum_offset + 1
        if has_extended_header and data[23] == 1 and hash_offset + 32 <= len(data):
            data[hash_offset : hash_offset + 32] = hashlib.sha256(data[:hash_offset]).digest()

        resource.queue_patch(Range.from_size(0, len(data)), bytes(data))
