import pytest
from pathlib import Path
from typing import Any, Dict, Union
from dataclasses import dataclass

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.esp import (
    ESPApp,
    ESPAppHeader,
    ESPAppExtendedHeader,
    ESPAppChecksum,
    ESPAppHash,
    ESPAppAttributes,
    ESPAppHeaderModifier,
    ESPAppHeaderModifierConfig,
    ESPAppPacker,
)
from ofrak.service.resource_service_i import ResourceFilter
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from pytest_ofrak.patterns.unpack_verify import UnpackAndVerifyPattern, UnpackAndVerifyTestCase
from pytest_ofrak.patterns.modify import ModifyPattern


def load_esp_asset(filename: str) -> bytes:
    """Load ESP binary from test assets."""
    asset_path = Path(__file__).parent / "assets" / "esp" / filename
    return asset_path.read_bytes()


@dataclass
class ESPAppUnpackTestCase(
    UnpackAndVerifyTestCase[
        str, Union[ESPAppHeader, ESPAppExtendedHeader, ESPAppChecksum, ESPAppHash, dict]
    ]
):
    binary_path: str
    has_extended_header: bool
    has_hash: bool
    num_sections: int
    entry_point: int
    checksum: int


class TestESPAppUnpackAndVerify(UnpackAndVerifyPattern):
    @pytest.fixture(
        params=[
            ESPAppUnpackTestCase(
                label="ESP32 App",
                binary_path="esp32_hello.bin",
                has_extended_header=True,
                has_hash=True,
                num_sections=5,
                entry_point=0x400829AC,
                checksum=0xEA,
                expected_results={
                    "header": {
                        "magic": 0xE9,
                        "entry_point": 0x400829AC,
                        "num_segments": 5,
                    },
                    "extended_header": {
                        "chip_id": 0x0000,  # ESP32
                    },
                    "checksum": {
                        "checksum": 0xEA,
                    },
                    "hash": {
                        "hash": bytes.fromhex(
                            "0750ce50194e3125f218af81d7a07ad0f5c23500ac487f047d77e89acadb6300"
                        ),
                    },
                },
                optional_results=set(),
            ),
            ESPAppUnpackTestCase(
                label="ESP32-S3 App",
                binary_path="esp32s3_hello.bin",
                has_extended_header=True,
                has_hash=True,
                num_sections=5,
                entry_point=0x40376EC4,
                checksum=0x70,
                expected_results={
                    "header": {
                        "magic": 0xE9,
                        "entry_point": 0x40376EC4,
                        "num_segments": 5,
                    },
                    "extended_header": {
                        "chip_id": 0x0009,  # ESP32-S3
                    },
                    "checksum": {
                        "checksum": 0x70,
                    },
                    "hash": {
                        "hash": bytes.fromhex(
                            "fec85e5eee92d767571cf058f150907c988c482cb2a71c0fc280f5202667832e"
                        ),
                    },
                },
                optional_results=set(),
            ),
            ESPAppUnpackTestCase(
                label="ESP8266 App",
                binary_path="esp8266_hello.bin",
                has_extended_header=False,
                has_hash=False,
                num_sections=2,
                entry_point=0x4010F480,
                checksum=0x2B,
                expected_results={
                    "header": {
                        "magic": 0xE9,
                        "entry_point": 0x4010F480,
                        "num_segments": 2,
                    },
                    "checksum": {
                        "checksum": 0x2B,
                    },
                },
                optional_results=set(),
            ),
        ],
        ids=lambda tc: tc.label,
    )
    async def unpack_verify_test_case(self, request) -> ESPAppUnpackTestCase:
        return request.param

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ESPAppUnpackTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        data = load_esp_asset(unpack_verify_test_case.binary_path)
        return await ofrak_context.create_root_resource(test_id, data)

    async def unpack(self, root_resource: Resource):
        await root_resource.identify()
        await root_resource.unpack()

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict:
        results: dict[
            str, Union[Union[ESPAppHeader, ESPAppExtendedHeader, ESPAppChecksum, ESPAppHash, dict]]
        ] = {}

        results["header"] = await unpacked_root_resource.get_only_child_as_view(
            ESPAppHeader, ResourceFilter(tags=(ESPAppHeader,))
        )
        try:  # ESP8266 doesn't have extended header or hash
            results["extended_header"] = await unpacked_root_resource.get_only_child_as_view(
                ESPAppExtendedHeader, ResourceFilter(tags=(ESPAppExtendedHeader,))
            )
            results["hash"] = await unpacked_root_resource.get_only_child_as_view(
                ESPAppHash, ResourceFilter(tags=(ESPAppHash,))
            )
        except:
            pass

        results["checksum"] = await unpacked_root_resource.get_only_child_as_view(
            ESPAppChecksum, ResourceFilter(tags=(ESPAppChecksum,))
        )

        return results

    async def verify_descendant(self, unpacked_descendant: Any, specified_result: Dict):
        if isinstance(unpacked_descendant, ESPAppHeader):
            for key, expected_value in specified_result.items():
                actual_value = getattr(unpacked_descendant, key)
                assert (
                    actual_value == expected_value
                ), f"Header {key}: {actual_value} != {expected_value}"

        elif isinstance(unpacked_descendant, ESPAppExtendedHeader):
            for key, expected_value in specified_result.items():
                actual_value = getattr(unpacked_descendant, key)
                assert (
                    actual_value == expected_value
                ), f"Extended header {key}: {actual_value} != {expected_value}"

        elif isinstance(unpacked_descendant, ESPAppChecksum):
            assert unpacked_descendant.checksum == specified_result["checksum"]

        elif isinstance(unpacked_descendant, ESPAppHash):
            assert unpacked_descendant.hash == specified_result["hash"]


class TestESPAppHeaderModification(ModifyPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        resource = await ofrak_context.create_root_resource(
            "test.bin", load_esp_asset("esp32_hello.bin")
        )
        await resource.identify()
        await resource.unpack()
        return resource

    async def modify(self, root_resource: Resource) -> None:
        header = await root_resource.get_only_child_as_view(
            ESPAppHeader, ResourceFilter(tags=(ESPAppHeader,))
        )
        self.original_entry_point = header.entry_point

        await header.resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=0x40080400)
        )

    async def verify(self, root_resource: Resource) -> None:
        header = await root_resource.get_only_child_as_view(
            ESPAppHeader, ResourceFilter(tags=(ESPAppHeader,))
        )
        assert header.entry_point == 0x40080400
        assert header.entry_point != self.original_entry_point


def _verify_with_esptool(packed_data: bytes, has_hash: bool = True):
    """Helper function to verify packed ESP app data with esptool."""
    import tempfile
    import subprocess
    import os

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as temp_file:
        temp_file.write(packed_data)
        temp_file.flush()

        try:
            result = subprocess.run(
                ["python", "-m", "esptool", "image_info", "--version", "2", temp_file.name],
                capture_output=True,
                text=True,
                timeout=30,
            )

            assert result.returncode == 0, f"esptool failed: {result.stderr}"

            output = result.stdout
            assert "Checksum:" in output, "esptool output should contain checksum information"
            assert "invalid" not in output.lower(), "Checksum should not be invalid"

            if has_hash:
                assert any(
                    word in output.lower() for word in ["hash", "digest", "sha256"]
                ), "Output should contain hash information for ESP32 images"

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            pytest.skip(f"esptool not available or timed out: {e}")
        finally:
            try:
                os.unlink(temp_file.name)
            except:
                pass


class TestESP32AppUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        app_data = load_esp_asset("esp32_hello.bin")
        return await ofrak_context.create_root_resource("test.bin", app_data)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        header = await unpacked_root_resource.get_only_child_as_view(
            ESPAppHeader, ResourceFilter(tags=(ESPAppHeader,))
        )
        original_entry = header.entry_point
        self.new_entry_point = 0x40080400 if original_entry != 0x40080400 else 0x40080500

        await header.resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=self.new_entry_point)
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        await repacked_root_resource.unpack()

        header = await repacked_root_resource.get_only_child_as_view(
            ESPAppHeader, ResourceFilter(tags=(ESPAppHeader,))
        )
        assert header.entry_point == self.new_entry_point

        attrs = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attrs.checksum_valid == True
        assert attrs.hash_valid == True

        packed_data = await repacked_root_resource.get_data()
        _verify_with_esptool(packed_data, has_hash=True)


class TestESP8266AppUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        app_data = load_esp_asset("esp8266_hello.bin")
        return await ofrak_context.create_root_resource("test.bin", app_data)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        header = await unpacked_root_resource.get_only_child_as_view(
            ESPAppHeader, ResourceFilter(tags=(ESPAppHeader,))
        )
        original_entry = header.entry_point
        self.new_entry_point = 0x40080400 if original_entry != 0x40080400 else 0x40080500

        await header.resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=self.new_entry_point)
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        await repacked_root_resource.unpack()

        header = await repacked_root_resource.get_only_child_as_view(
            ESPAppHeader, ResourceFilter(tags=(ESPAppHeader,))
        )
        assert header.entry_point == self.new_entry_point

        attrs = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attrs.checksum_valid == True

        packed_data = await repacked_root_resource.get_data()
        _verify_with_esptool(packed_data, has_hash=False)
