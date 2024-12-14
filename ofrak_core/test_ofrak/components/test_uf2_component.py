import logging
import pytest
from ofrak.core.addressable import Addressable
from ofrak.core.memory_region import MemoryRegion
from pathlib import Path

from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceAttributeRangeFilter, ResourceFilter
from ofrak.core.uf2 import Uf2File, Uf2FilePacker, Uf2Unpacker
from ofrak.core.strings import StringPatchingModifier, StringPatchingConfig
import test_ofrak.components

from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

LOGGER = logging.getLogger(__name__)

FILENAME = "rp2-pico-20220618-v1.19.1.uf2"
EXPECTED_DATA = b"Raspberry Pi Pico with RP1337"


def test_uf2_identify(ofrak_context: OFRAKContext) -> None:
    asset_path = Path(test_ofrak.components.ASSETS_DIR, FILENAME)
    root_resource = ofrak_context.create_root_resource_from_file(str(asset_path))
    root_resource.identify()
    assert root_resource.has_tag(Uf2File), "Expected resource to have tag Uf2File"


@pytest.mark.skipif_missing_deps([Uf2FilePacker, Uf2Unpacker])
class TestUf2UnpackModifyPack(UnpackModifyPackPattern):
    def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        asset_path = Path(test_ofrak.components.ASSETS_DIR, FILENAME)
        root_resource = ofrak_context.create_root_resource_from_file(str(asset_path))
        root_resource.save()
        return root_resource

    def unpack(self, uf2_resource: Resource) -> None:
        uf2_resource.unpack()
        print(uf2_resource.summarize_tree())
        assert uf2_resource.has_tag(Uf2File), "Expected resource to have tag Uf2File"

    def modify(self, unpacked_uf2_resource: Resource) -> None:
        memory_region = unpacked_uf2_resource.get_only_child(
            r_filter=ResourceFilter(
                tags=(MemoryRegion,),
                attribute_filters=(
                    ResourceAttributeRangeFilter(Addressable.VirtualAddress, 0x10000),
                ),
            )
        )

        string_patch_config = StringPatchingConfig(
            offset=0x3C7AC, string="RP1337", null_terminate=False
        )
        memory_region.run(StringPatchingModifier, string_patch_config)

    def repack(self, uf2_resource: Resource) -> None:
        uf2_resource.pack()

    def verify(self, repacked_uf2_resource: Resource) -> None:
        resource_data = repacked_uf2_resource.get_data()
        unpacked_data = resource_data[0x78EB5:0x78ED2]
        assert unpacked_data == EXPECTED_DATA
