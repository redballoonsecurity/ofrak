import pytest
from pathlib import Path
from typing import Any, Dict
from dataclasses import dataclass

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.esp import (
    ESPFlash,
    ESPPartitionTable,
    ESPFlashSection,
    ESPPartitionType,
    ESPPartitionSubtype,
    ESPPartitionFlag,
    ESP_PARTITION_TABLE_OFFSET,
    ESP_BOOTLOADER_OFFSET,
)
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter
from ofrak.core.program_section import NamedProgramSection
from pytest_ofrak.patterns.unpack_verify import UnpackAndVerifyPattern, UnpackAndVerifyTestCase


def load_esp_flash_asset(filename: str) -> bytes:
    """Load ESP flash binary from test assets."""
    asset_path = Path(__file__).parent / "assets" / "esp" / filename
    return asset_path.read_bytes()


# Fixtures
@pytest.fixture
def esp32_flash_data():
    """Fixture providing test ESP32 flash data from assets"""
    return load_esp_flash_asset("esp32_basic_flash.bin")


@pytest.fixture
def esp32s3_flash_data():
    """Fixture providing test ESP32-S3 flash data from assets"""
    return load_esp_flash_asset("esp32s3_basic_flash.bin")


@pytest.fixture
def esp_flash_data():
    """Fixture providing default ESP flash data"""
    return load_esp_flash_asset("esp32_basic_flash.bin")


@pytest.fixture
def esp_app_data():
    """Fixture providing ESP app data from assets"""
    from test_ofrak.components.test_esp_app_component import load_esp_asset

    return load_esp_asset("esp32_hello.bin")


# Test case data classes
@dataclass
class ESPFlashUnpackTestCase(UnpackAndVerifyTestCase):
    binary_path: str
    flash_size: int
    has_bootloader: bool
    has_partition_table: bool
    min_sections: int


@dataclass
class ESPFlashModifyTestCase:
    label: str
    binary_path: str
    entry_index: int
    new_type: ESPPartitionType
    new_subtype: ESPPartitionSubtype
    new_flag: ESPPartitionFlag


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
                optional_results={"app0", "app1", "nvs", "otadata", "phy_init", "factory"},
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
                optional_results={"app0", "app1", "nvs", "otadata", "phy_init", "factory"},
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
        except:
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
        except:
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

    # Check if app partition contains valid ESP app
    for app_entry in app_partitions:
        partition = await app_entry.get_body()
        partition_data = await partition.resource.get_data()

        # Check for ESP app magic at start of partition
        if len(partition_data) > 0:
            if partition_data[0] in [0xE9, 0xEA]:  # ESP app magic bytes
                assert True
                return
    assert False, "No valid ESP app found in app partitions"
