"""
Test the OpenWrt TRX component functionality.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import os
import struct

from ofrak_type.range import Range

from ofrak import OFRAKContext
from ofrak.core.openwrt import openwrt_crc32, OpenWrtTrxHeader
from ofrak.resource import Resource
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from . import ASSETS_DIR


class TestOpenWrtTrxUnpackModifyPack(UnpackModifyPackPattern):
    """
    Test that an OpenWrt TRX image can be unpacked, modified, and repacked correctly.

    This test verifies that:
    - The TRX image can be successfully unpacked into its constituent parts
    - A modification (replacing first partition with null bytes) can be applied
    - The modified image can be repacked while maintaining correct CRC32 checksums
    """

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
        await resource.unpack()

    async def modify(self, resource: Resource) -> None:
        """
        The modification for the OpenWrtTrx test is to replace the entirety of the first partition
        with 4 null bytes
        """
        children_by_offset = sorted(
            [
                (await child.get_data_range_within_root(), child)
                for child in await resource.get_children()
                if not child.has_tag(OpenWrtTrxHeader)
            ],
            key=lambda x: x[0].start,
        )
        partition = children_by_offset[0][1]
        original_size = await partition.get_data_length()
        partition.queue_patch(Range(0, original_size), b"\x00\x00\x00\x00")
        await partition.save()

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

    This test verifies that:
    - The TRX image can be successfully unpacked and repacked without modification
    - The resulting image is identical to the original image
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
    Test that an OpenWrt TRX image without a valid rootfs segment can be handled.

    This test verifies that:
    - The TRX image can be unpacked even when it lacks a standard rootfs
    - The repacked image maintains correct CRC32 checksums
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
        children_start = {
            await child.get_data(Range(0, 4)) for child in await resource.get_children()
        }
        assert b"UBI#" in children_start

    async def verify(self, resource: Resource) -> None:
        resource_data = await resource.get_data()
        assert resource_data.startswith(b"HDR0")
        trx_crc = struct.unpack("<I", resource_data[8:12])[0]
        assert trx_crc == openwrt_crc32(resource_data[12:])
        assert trx_crc == 0x36858182
