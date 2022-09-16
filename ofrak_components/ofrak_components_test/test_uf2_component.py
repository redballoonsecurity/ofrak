from uf2 import uf2conv
import logging

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak_components.uf2 import Uf2Data
from ofrak.core.strings import StringPatchingModifier, StringPatchingConfig

from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

LOGGER = logging.getLogger(__name__)

INITIAL_DATA = b"Hello World"
EXPECTED_DATA = b"Hello OFRAK" + b"\x00" * 245
TARGET_UF2_FILE = "hello_uf2.uf2"
UF2_ENTRY_NAME = "hello_uf2_file"


class TestUf2UnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        packed_data = uf2conv.convert_to_uf2(INITIAL_DATA)
        root_resource = await ofrak_context.create_root_resource("uf2", packed_data)
        root_resource.add_tag(GenericBinary)
        await root_resource.save()
        return root_resource

    async def unpack(self, uf2_resource: Resource) -> None:
        await uf2_resource.unpack()
        assert uf2_resource.has_tag(Uf2Data), "Expected resource to have tag Uf2Data"

    async def modify(self, unpacked_uf2_resource: Resource) -> None:
        uf2_r = await unpacked_uf2_resource.get_only_child()
        string_patch_config = StringPatchingConfig(6, "OFRAK")
        await uf2_r.run(StringPatchingModifier, string_patch_config)
        LOGGER.info(await uf2_r.get_data())

    async def repack(self, uf2_resource: Resource) -> None:
        LOGGER.info(await uf2_resource.get_data())
        await uf2_resource.pack()

    async def verify(self, repacked_uf2_resource: Resource) -> None:
        resource_data = await repacked_uf2_resource.get_data()
        unpacked_data = uf2conv.convert_from_uf2(resource_data)
        LOGGER.info(len(unpacked_data))
        LOGGER.info(len(EXPECTED_DATA))
        assert unpacked_data == EXPECTED_DATA
        assert repacked_uf2_resource.has_tag(Uf2Data)
