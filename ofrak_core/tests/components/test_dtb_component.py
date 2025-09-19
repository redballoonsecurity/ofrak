import os

import fdt

from .. import components
from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter
from ofrak.core.dtb import DeviceTreeBlob, DtbProperty, DtbNode, match_dtb_magic
from ofrak.core.strings import StringPatchingModifier, StringPatchingConfig
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern


class TestDeviceTreeBlobUnpackPackIdentity(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        dtb_path = os.path.join(components.ASSETS_DIR, "imx7d-sdb.dtb")
        return await ofrak_context.create_root_resource_from_file(dtb_path)

    async def unpack(self, resource: Resource) -> None:
        await resource.unpack()

    async def modify(self, unpacked_resource: Resource) -> None:
        pass

    async def repack(self, resource: Resource) -> None:
        await resource.pack()

    async def verify(self, repacked_resource: Resource):
        original_dtb_path = os.path.join(components.ASSETS_DIR, "imx7d-sdb.dtb")
        with open(original_dtb_path, "rb") as f:
            original_dtb_data = f.read()
        repacked_dtb_data = await repacked_resource.get_data()

        # Assert that the original and repacked DTBs are identical using fdt.diff() method
        (dtb_diff_common, dtb_diff_only_original, dtb_diff_only_repacked) = fdt.diff(
            fdt.parse_dtb(original_dtb_data), fdt.parse_dtb(repacked_dtb_data)
        )
        assert not dtb_diff_common.empty
        assert dtb_diff_only_original.empty, (
            f"Differences only in original DTB: " f"{dtb_diff_only_original}"
        )
        assert dtb_diff_only_repacked.empty, (
            f"Differences only in repacked DTB: " f"{dtb_diff_only_repacked}"
        )


class TestDeviceTreeBlobUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        dtb_path = os.path.join(components.ASSETS_DIR, "imx7d-sdb.dtb")
        return await ofrak_context.create_root_resource_from_file(dtb_path)

    async def unpack(self, resource: Resource) -> None:
        await resource.unpack()

    async def modify(self, unpacked_resource: Resource) -> None:
        # Add a node
        dtb_view = await unpacked_resource.view_as(DeviceTreeBlob)
        root_node = await dtb_view.get_node_by_path("/")
        await root_node.resource.create_child_from_view(
            DtbNode(name="great-new-node"),
            data=b"",
        )

        # Delete a node
        child_to_delete = await dtb_view.get_node_by_path("/sound-hdmi")
        await child_to_delete.resource.delete()
        await child_to_delete.resource.save()

        # Change a DtbProperty value
        node = await dtb_view.get_node_by_path("/backlight")
        prop = await node.resource.get_only_descendant_as_view(
            v_type=DtbProperty,
            r_filter=ResourceFilter(
                tags=(DtbProperty,),
                attribute_filters=(
                    ResourceAttributeValueFilter(DtbProperty.DtbPropertyName, "status"),
                ),
            ),
        )

        prop_path = await prop.get_path()

        assert prop_path == "/backlight/status", f'Expected "/backlight/status", got {prop_path}'

        child_text_string_config = StringPatchingConfig(0, "hey!")
        await prop.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, resource: Resource) -> None:
        await resource.pack()

    async def verify(self, repacked_resource: Resource):
        original_dtb_path = os.path.join(components.ASSETS_DIR, "imx7d-sdb.dtb")
        with open(original_dtb_path, "rb") as f:
            original_dtb_data = f.read()
        repacked_dtb_data = await repacked_resource.get_data()

        (dtb_diff_common, dtb_diff_only_original, dtb_diff_only_repacked) = fdt.diff(
            fdt.parse_dtb(original_dtb_data), fdt.parse_dtb(repacked_dtb_data)
        )

        assert not dtb_diff_common.empty
        # Assert the original DTB's /backlight:status unmodified property string is in the diff
        assert dtb_diff_only_original.get_property("status", "/backlight").value == "okay"

        # Assert that only the original DTB contains the sound-hdmi node
        assert dtb_diff_only_original.exist_node("/sound-hdmi")

        # Assert the repacked DTB's /backlight:status modified property string is in the diff
        assert dtb_diff_only_repacked.get_property("status", "/backlight").value == "hey!"

        # Assert that the repacked DTB contains an empty node named "great-new-node"
        assert dtb_diff_only_repacked.get_node("/great-new-node").empty


def test_dtb_raw_magic_pattern():
    """
    Test that DTB raw pattern callable is correct.
    """
    dtb_path = os.path.join(components.ASSETS_DIR, "imx7d-sdb.dtb")
    with open(dtb_path, "rb") as f:
        data = f.read()
    assert match_dtb_magic(data)
