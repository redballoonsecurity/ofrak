import os
import struct

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from ofrak_type.range import Range
from ofrak.core.openwrt import openwrt_crc32
from ofrak.core.ubi import Ubi
from ofrak.core.binary import GenericBinary
from test_ofrak.components import ASSETS_DIR


class TestOpenWrtTrxUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create a root resource from the test image stored in Git LFS.
        """
        testfile_path = os.path.join(
            ASSETS_DIR, "openwrt-21.02.1-bcm47xx-mips74k-asus_rt-n14uhp-squashfs.trx"
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
        partitions = await resource.get_descendants_as_view(
            GenericBinary, max_depth=1, r_filter=ResourceFilter(tags=(GenericBinary,))
        )
        partition = partitions[0]

        original_size = await partition.resource.get_data_length()
        partition.resource.queue_patch(Range(0, original_size), b"\x00\x00\x00\x00")

        await partition.resource.save()

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


class TestOpenWrtTrxUnpackRepackNullRootfs(TestOpenWrtTrxUnpackModifyPack):
    """
    Unpack and repack an image without a valid rootfs segment - this seems to be seen on most non-MIPS boards
    """

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create a root resource from the test image stored in Git LFS.
        """
        testfile_path = os.path.join(
            ASSETS_DIR, "openwrt-19.07.0-bcm53xx-buffalo-wxr-1900dhp-squashfs.trx"
        )
        image_path = os.path.abspath(os.path.join(os.path.dirname(__file__), testfile_path))
        resource = await ofrak_context.create_root_resource_from_file(image_path)
        return resource

    async def unpack(self, resource: Resource) -> None:
        await super().unpack(resource)

        flash = await resource.get_only_descendant_as_view(
            Ubi, r_filter=ResourceFilter(tags=(Ubi,))
        )

        flash_data = await flash.resource.get_data()
        assert flash_data.startswith(b"UBI#")

    async def verify(self, resource: Resource) -> None:
        resource_data = await resource.get_data()
        assert resource_data.startswith(b"HDR0")
        trx_crc = struct.unpack("<I", resource_data[8:12])[0]
        assert trx_crc == openwrt_crc32(resource_data[12:])
        assert trx_crc == 0x6B550F3C
