import logging
from ofrak.core.addressable import Addressable
from ofrak.core.memory_region import MemoryRegion
from pathlib import Path

from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceAttributeRangeFilter, ResourceFilter
from ofrak_components.uf2 import Uf2File
from ofrak.core.strings import StringPatchingModifier, StringPatchingConfig
import ofrak_components_test

from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

LOGGER = logging.getLogger(__name__)

FILENAME = "rp2-pico-20220618-v1.19.1.uf2"
EXPECTED_DATA = b"Raspberry Pi Pico with RP1337"


class TestUf2UnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        asset_path = Path(ofrak_components_test.ASSETS_DIR, FILENAME)
        root_resource = await ofrak_context.create_root_resource_from_file(str(asset_path))
        root_resource.add_tag(Uf2File)
        await root_resource.save()
        return root_resource

    async def unpack(self, uf2_resource: Resource) -> None:
        await uf2_resource.unpack()
        print(await uf2_resource.summarize_tree())
        assert uf2_resource.has_tag(Uf2File), "Expected resource to have tag Uf2File"

    async def modify(self, unpacked_uf2_resource: Resource) -> None:
        memory_region = await unpacked_uf2_resource.get_only_child(
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
        await memory_region.run(StringPatchingModifier, string_patch_config)

    async def repack(self, uf2_resource: Resource) -> None:
        await uf2_resource.pack()

    async def verify(self, repacked_uf2_resource: Resource) -> None:
        resource_data = await repacked_uf2_resource.get_data()
        unpacked_data = resource_data[0x78EB5:0x78ED2]
        assert unpacked_data == EXPECTED_DATA
        assert repacked_uf2_resource.has_tag(Uf2File)
