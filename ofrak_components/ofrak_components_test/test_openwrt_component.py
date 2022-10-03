import os
import struct

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from ofrak_type.range import Range
from ofrak_components.openwrt import OpenWrtTrxKernel, openwrt_crc32


class TestOpenWrtTrxUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create a root resource from the test image stored in Git LFS.
        """
        assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
        testfile_path = os.path.join(
            assets_dir, "openwrt-21.02.1-bcm47xx-mips74k-asus_rt-n14uhp-squashfs.trx"
        )
        image_path = os.path.abspath(os.path.join(os.path.dirname(__file__), testfile_path))
        resource = await ofrak_context.create_root_resource_from_file(image_path)
        return resource

    async def unpack(self, resource: Resource) -> None:
        await resource.unpack_recursively()

    async def modify(self, resource: Resource) -> None:
        """
        The modification for the OpenWrtTrx test is to replace the entirety of the kernel
        with 4 null bytes
        """
        kernel = await resource.get_only_child_as_view(
            OpenWrtTrxKernel, ResourceFilter.with_tags(OpenWrtTrxKernel)
        )
        original_size = await kernel.resource.get_data_length()
        kernel.resource.queue_patch(Range(0, original_size), b"\x00\x00\x00\x00")
        await kernel.resource.save()

    async def repack(self, resource: Resource) -> None:
        await resource.pack_recursively()

    async def verify(self, resource: Resource) -> None:
        resource_data = await resource.get_data()
        trx_crc = struct.unpack("<I", resource_data[8:12])[0]
        assert trx_crc == openwrt_crc32(resource_data[12:])
        assert resource_data.startswith(b"HDR0")


class TestOpenWrtTrxUnpackRepackIdempotency(TestOpenWrtTrxUnpackModifyPack):
    """
    Unpack and repack (non-recursively) and check if the resulting and original OpenWrt TRX image
    are the exact same
    """

    async def unpack(self, resource: Resource) -> None:
        await resource.unpack()

    async def modify(self, resource: Resource) -> None:
        return

    async def repack(self, resource: Resource) -> None:
        await resource.pack()

    async def verify(self, resource: Resource) -> None:
        resource_data = await resource.get_data()
        assert resource_data.startswith(b"HDR0")
        trx_crc = struct.unpack("<I", resource_data[8:12])[0]
        assert trx_crc == openwrt_crc32(resource_data[12:])
        assert trx_crc == 0xB83AFAD6
