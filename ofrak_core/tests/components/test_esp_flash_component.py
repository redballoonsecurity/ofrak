import struct

import pytest
from pathlib import Path
from typing import Any, Dict
from dataclasses import dataclass

from ofrak import OFRAKContext
from ofrak.component.unpacker import UnpackerError
from ofrak_type.error import NotFoundError
from ofrak.resource import Resource
from ofrak.core.esp import (
    ESPFlash,
    ESPFlashAttributes,
    ESPFlashUnpacker,
    ESPPartitionTable,
    ESPPartitionTableEntryModifier,
    ESPPartitionTableEntryModifierConfig,
    ESPFlashSection,
    ESPPartitionType,
    ESPPartitionSubtype,
    ESPPartitionFlag,
    ESP_PARTITION_TABLE_OFFSET,
    ESP_BOOTLOADER_OFFSET,
)
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceAttributeValueFilter,
)
from ofrak.core.program_section import NamedProgramSection
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyPattern,
    UnpackAndVerifyTestCase,
)


def load_esp_flash_asset(filename: str) -> bytes:
    """Load ESP flash binary from test assets."""
    asset_path = Path(__file__).parent / "assets" / "esp" / filename
    return asset_path.read_bytes()


# Fixtures
@pytest.fixture
def esp_flash_data():
    """Fixture providing default ESP flash data"""
    return load_esp_flash_asset("esp32_basic_flash.bin")


# Test case data classes
@dataclass
class ESPFlashUnpackTestCase(UnpackAndVerifyTestCase):
    binary_path: str
    flash_size: int
    has_bootloader: bool
    has_partition_table: bool
    min_sections: int


# UnpackAndVerifyPattern implementation for ESP flash unpacking
class TestESPFlashUnpackAndVerify(UnpackAndVerifyPattern):
    @pytest.fixture(
        params=[
            ESPFlashUnpackTestCase(
                label="ESP32 Flash",
                binary_path="esp32_basic_flash.bin",
                flash_size=4194304,  # 4MB
                has_bootloader=True,
                has_partition_table=True,
                min_sections=2,
                expected_results={
                    "bootloader": {
                        "offset": ESP_BOOTLOADER_OFFSET,
                        "type": ESPFlashSection,
                    },
                    "partition_table": {
                        "offset": ESP_PARTITION_TABLE_OFFSET,
                        "type": ESPPartitionTable,
                    },
                },
                optional_results={
                    "app0",
                    "app1",
                    "nvs",
                    "otadata",
                    "phy_init",
                    "factory",
                },
            ),
            ESPFlashUnpackTestCase(
                label="ESP32-S3 Flash",
                binary_path="esp32s3_basic_flash.bin",
                flash_size=4194304,  # 4MB
                has_bootloader=True,
                has_partition_table=True,
                min_sections=2,
                expected_results={
                    "bootloader": {
                        "offset": ESP_BOOTLOADER_OFFSET,
                        "type": ESPFlashSection,
                    },
                    "partition_table": {
                        "offset": ESP_PARTITION_TABLE_OFFSET,
                        "type": ESPPartitionTable,
                    },
                },
                optional_results={
                    "app0",
                    "app1",
                    "nvs",
                    "otadata",
                    "phy_init",
                    "factory",
                },
            ),
        ],
        ids=lambda tc: tc.label,
    )
    async def unpack_verify_test_case(self, request) -> ESPFlashUnpackTestCase:
        return request.param

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ESPFlashUnpackTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        data = load_esp_flash_asset(unpack_verify_test_case.binary_path)
        return await ofrak_context.create_root_resource(test_id, data)

    async def unpack(self, root_resource: Resource):
        await root_resource.identify()
        await root_resource.unpack()

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict[str, Any]:
        results = {}

        # Get bootloader
        try:
            bootloader = await unpacked_root_resource.get_only_child_as_view(
                ESPFlashSection,
                ResourceFilter(
                    tags=(ESPFlashSection,),
                    attribute_filters=[
                        ResourceAttributeValueFilter(NamedProgramSection.SectionName, "bootloader")
                    ],
                ),
            )
            results["bootloader"] = bootloader
        except NotFoundError:
            pass

        # Get partition table
        try:
            partition_table = await unpacked_root_resource.get_only_child_as_view(
                ESPPartitionTable, ResourceFilter(tags=(ESPPartitionTable,))
            )
            results["partition_table"] = partition_table

            # Get partition entries
            entries = list(await partition_table.get_entries())
            for entry in entries:
                results[entry.name] = entry
        except NotFoundError:
            pass

        return results

    async def verify_descendant(self, unpacked_descendant: Any, specified_result: Dict):
        if "offset" in specified_result:
            assert unpacked_descendant.virtual_address == specified_result["offset"]

        if "type" in specified_result:
            assert isinstance(unpacked_descendant, specified_result["type"])


@pytest.mark.asyncio
async def test_esp_partition_table_entries(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test partition table entry parsing."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()

    # Get partition table
    flash = await resource.view_as(ESPFlash)
    partition_table = await flash.get_partition_table()
    entries = list(await partition_table.get_entries())
    assert len(entries) > 0

    # Check first entry
    first_entry = entries[0]
    assert isinstance(first_entry.type, ESPPartitionType)
    assert isinstance(first_entry.subtype, ESPPartitionSubtype)
    assert first_entry.name != ""

    # Get corresponding partition
    partition = await first_entry.get_body()
    # The partition and entry should have the same name and partition index
    assert partition.name == first_entry.name
    assert partition.partition_index == first_entry.partition_index
    # The partition should have some reasonable size (actual partition data size)
    assert partition.size > 0


@pytest.mark.asyncio
async def test_esp_flash_with_app_partition(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test handling flash image with app partitions."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()

    # Find app partitions
    flash = await resource.view_as(ESPFlash)
    partition_table = await flash.get_partition_table()
    entries = list(await partition_table.get_entries())

    app_partitions = [e for e in entries if e.type == ESPPartitionType.APP]
    assert len(app_partitions) > 0

    # At least one app partition's payload must begin with an ESP app magic byte.
    leading_bytes = []
    for app_entry in app_partitions:
        partition = await app_entry.get_body()
        partition_data = await partition.resource.get_data()
        if partition_data:
            leading_bytes.append(partition_data[0])
    assert any(
        b in (0xE9, 0xEA) for b in leading_bytes
    ), f"no app partition payload starts with an ESP app magic (got {[hex(b) for b in leading_bytes]})"


@pytest.mark.asyncio
async def test_esp_flash_analyzer(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """ESPFlashAnalyzer summarizes the partition table: counts, total size, overlap, unused space."""
    resource = await ofrak_context.create_root_resource("analyze.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()

    flash = await resource.view_as(ESPFlash)
    entries = list(await (await flash.get_partition_table()).get_entries())

    attributes = await resource.analyze(ESPFlashAttributes)
    assert attributes.total_partitions == len(entries)
    assert attributes.total_flash_size == len(esp_flash_data)
    # A well-formed image's partitions do not overlap.
    assert attributes.has_overlapping_partitions is False
    assert attributes.unused_space >= 0


@pytest.mark.asyncio
async def test_esp_partition_get_header(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """ESPPartition.get_header() returns the table entry for a partition (inverse of get_body())."""
    resource = await ofrak_context.create_root_resource("hdr.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()

    flash = await resource.view_as(ESPFlash)
    entry = list(await (await flash.get_partition_table()).get_entries())[0]
    partition = await entry.get_body()

    header = await partition.get_header()
    assert isinstance(header, type(entry))
    assert header.partition_index == entry.partition_index
    assert header.name == entry.name
    assert header.type == entry.type


@pytest.mark.asyncio
async def test_esp_partition_table_entry_modifier(
    ofrak_context: OFRAKContext, esp_flash_data: bytes
):
    """
    ESPPartitionTableEntryModifier changes only the requested field of an entry; the partition's
    offset/size and the entry magic are preserved verbatim.
    """
    resource = await ofrak_context.create_root_resource("mod.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()

    flash = await resource.view_as(ESPFlash)
    entries = list(await (await flash.get_partition_table()).get_entries())
    # get_entries() order is not guaranteed, so pin a stable entry by its partition index.
    entry = min(entries, key=lambda e: e.partition_index)
    target_index = entry.partition_index
    original = await entry.resource.get_data()
    assert len(original) == 32

    # Pick a subtype different from the current one.
    new_subtype = (
        ESPPartitionSubtype.OTA_1
        if original[3] == ESPPartitionSubtype.OTA_0.value
        else ESPPartitionSubtype.OTA_0
    )
    await entry.resource.run(
        ESPPartitionTableEntryModifier,
        ESPPartitionTableEntryModifierConfig(subtype=new_subtype),
    )

    modified = await entry.resource.get_data()
    assert modified[3] == new_subtype.value  # subtype byte changed
    assert modified[0:2] == original[0:2]  # entry magic preserved
    assert modified[2] == original[2]  # type preserved
    assert modified[4:12] == original[4:12]  # partition offset + size preserved
    assert modified[12:28] == original[12:28]  # label preserved
    assert modified[28:32] == original[28:32]  # flags preserved

    # The change propagates to the whole flash image: re-unpacking reflects the new subtype.
    reloaded = await ofrak_context.create_root_resource(
        "mod_reloaded.bin", await resource.get_data()
    )
    await reloaded.identify()
    await reloaded.unpack()
    reloaded_entries = list(
        await (await (await reloaded.view_as(ESPFlash)).get_partition_table()).get_entries()
    )
    reloaded_entry = next(e for e in reloaded_entries if e.partition_index == target_index)
    assert reloaded_entry.subtype == new_subtype


@pytest.mark.asyncio
async def test_esp_partition_table_entry_modifier_all_fields(
    ofrak_context: OFRAKContext, esp_flash_data: bytes
):
    """Every config field is written to the entry, and the entry magic is preserved."""
    resource = await ofrak_context.create_root_resource("modall.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()

    flash = await resource.view_as(ESPFlash)
    entries = list(await (await flash.get_partition_table()).get_entries())
    entry = min(entries, key=lambda e: e.partition_index)

    await entry.resource.run(
        ESPPartitionTableEntryModifier,
        ESPPartitionTableEntryModifierConfig(
            type=ESPPartitionType.DATA,
            subtype=ESPPartitionSubtype.NVS,
            virtual_address=0x110000,
            size=0x2000,
            name="patched",
            flag=ESPPartitionFlag.ENCRYPTED,
        ),
    )
    m = await entry.resource.get_data()
    assert m[0:2] == b"\xAA\x50"  # entry magic (0x50AA) preserved
    assert m[2] == ESPPartitionType.DATA.value
    assert m[3] == ESPPartitionSubtype.NVS.value
    assert struct.unpack_from("<I", m, 4)[0] == 0x110000  # offset (config.virtual_address)
    assert struct.unpack_from("<I", m, 8)[0] == 0x2000  # size
    assert m[12:28].rstrip(b"\x00") == b"patched"  # label
    assert struct.unpack_from("<I", m, 28)[0] == ESPPartitionFlag.ENCRYPTED.value


@pytest.mark.asyncio
async def test_esp_flash_unpacker_rejects_malformed(
    ofrak_context: OFRAKContext, esp_flash_data: bytes
):
    """The flash unpacker raises a clean UnpackerError on truncated/corrupt images."""

    async def expect_error(data: bytes):
        r = await ofrak_context.create_root_resource("bad_flash.bin", data)
        # These images intentionally fail the identifier's checks, so tag directly to drive unpack.
        r.add_tag(ESPFlash)
        with pytest.raises(UnpackerError):
            await r.run(ESPFlashUnpacker)

    # Too small to hold a partition table (sliced just past the table magic).
    await expect_error(esp_flash_data[: ESP_PARTITION_TABLE_OFFSET + 16])
    # Big enough, table magic present, but the bootloader magic byte is corrupted.
    no_boot = bytearray(esp_flash_data[:0x8100])
    no_boot[ESP_BOOTLOADER_OFFSET] = 0x00
    await expect_error(bytes(no_boot))
    # Bootloader magic present, but the partition-table magic is corrupted.
    no_pt = bytearray(esp_flash_data[:0x8100])
    no_pt[ESP_PARTITION_TABLE_OFFSET : ESP_PARTITION_TABLE_OFFSET + 2] = b"\x00\x00"
    await expect_error(bytes(no_pt))


@pytest.mark.asyncio
async def test_esp_flash_analyzer_detects_overlap(
    ofrak_context: OFRAKContext, esp_flash_data: bytes
):
    """ESPFlashAnalyzer flags overlapping partitions (e.g. a corrupted/crafted table)."""
    data = bytearray(esp_flash_data)
    pt = ESP_PARTITION_TABLE_OFFSET
    e0_offset, e0_size = struct.unpack_from("<II", data, pt + 4)  # entry 0 offset + size
    # Move entry 1's payload to start inside entry 0's range so the two partitions overlap.
    struct.pack_into("<I", data, pt + 32 + 4, e0_offset + max(1, e0_size // 2))

    root = await ofrak_context.create_root_resource("overlap.bin", bytes(data))
    await root.identify()
    await root.unpack()
    attrs = await root.analyze(ESPFlashAttributes)
    assert attrs.has_overlapping_partitions is True


@pytest.mark.asyncio
async def test_esp_flash_analyzer_skips_out_of_dump_partition(
    ofrak_context: OFRAKContext, esp_flash_data: bytes
):
    """
    A partition whose payload lies past the end of the dump gets no ESPPartition child; the
    analyzer must skip that entry (no body) instead of raising.
    """
    data = bytearray(esp_flash_data)
    pt = ESP_PARTITION_TABLE_OFFSET
    # Point entry 1's payload offset beyond the end of the image -> no ESPPartition is created.
    struct.pack_into("<I", data, pt + 32 + 4, len(data) + 0x1000)

    root = await ofrak_context.create_root_resource("oob.bin", bytes(data))
    await root.identify()
    await root.unpack()
    attrs = await root.analyze(ESPFlashAttributes)  # must not raise NotFoundError
    assert attrs.total_partitions >= 1


@pytest.mark.asyncio
async def test_esp_flash_navigation(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """ESPFlash.get_sections / get_section_by_name and ESPPartitionTable.get_section_by_name."""
    resource = await ofrak_context.create_root_resource("nav.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()

    flash = await resource.view_as(ESPFlash)
    sections = list(await flash.get_sections())
    assert any(s.name == "bootloader" for s in sections)

    bootloader = await flash.get_section_by_name("bootloader")
    assert bootloader.name == "bootloader"

    partition_table = await flash.get_partition_table()
    entries = list(await partition_table.get_entries())
    names = [e.name for e in entries]
    unique_name = next(n for n in names if names.count(n) == 1)
    partition = await partition_table.get_section_by_name(unique_name)
    assert partition.name == unique_name


@pytest.mark.asyncio
async def test_esp_flash_decodes_corrupt_and_encrypted_entries(
    ofrak_context: OFRAKContext, esp_flash_data: bytes
):
    """Unrecognized type/subtype decode to INVALID and the encrypted flag is recognized."""
    data = bytearray(esp_flash_data)
    pt = ESP_PARTITION_TABLE_OFFSET
    data[pt + 2] = 0x99  # entry 0 type: not APP/DATA -> INVALID
    data[pt + 3] = 0xCC  # entry 0 subtype: not a known subtype -> INVALID
    data[pt + 28] = 0x01  # entry 0 flag: encrypted
    data[pt + 32 + 28] = 0x02  # entry 1 flag: not 0/1 -> INVALID

    root = await ofrak_context.create_root_resource("corrupt_entries.bin", bytes(data))
    await root.identify()
    await root.unpack()
    partition_table = await (await root.view_as(ESPFlash)).get_partition_table()
    entries = {e.partition_index: e for e in await partition_table.get_entries()}
    assert entries[0].type == ESPPartitionType.INVALID
    assert entries[0].subtype == ESPPartitionSubtype.INVALID
    assert entries[0].flag == ESPPartitionFlag.ENCRYPTED
    assert entries[1].flag == ESPPartitionFlag.INVALID
