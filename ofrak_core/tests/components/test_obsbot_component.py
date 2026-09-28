"""
Test OBSBOT and AMAC firmware components.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""

import hashlib
import struct
import zlib
import pytest

from ofrak import OFRAKContext
from ofrak.core.obsbot import (
    MAGIC,
    AMAC_MAGIC,
    FormatError,
    ObsbotFirmwareBundle,
    ObsbotFirmwareComponent,
    ObsbotFirmwareBundleAttributes,
    ObsbotFirmwareIdentifier,
    ObsbotFirmwareBundleAnalyzer,
    ObsbotFirmwareUnpacker,
    ObsbotFirmwarePacker,
    AmacFirmwareBundle,
    AmacFirmwareBundleAttributes,
    AmacFirmwareIdentifier,
    AmacFirmwareBundleAnalyzer,
    AmacFirmwareUnpacker,
    AmacFirmwarePacker,
    parse_bundle,
    rebuild_bundle,
    parse_amac,
    rebuild_amac,
)
from ofrak.core.binary import GenericBinary, BinaryPatchConfig, BinaryPatchModifier


def make_synthetic_obsbot_bundle(components: list[tuple[str, int, bytes]]) -> bytes:
    count = len(components)
    header_size = 0x100 + count * 0x100
    raw_header = bytearray(header_size)
    offset = header_size
    payloads = []
    for idx, (name, type_id, data) in enumerate(components):
        payloads.append(data)
        record = bytearray(0x100)
        struct.pack_into("<III", record, 0, type_id, len(data), offset)
        record[0x3C:0x40] = b"\x01\x00\x00\x00"
        struct.pack_into("<I", record, 0x40, 0)
        struct.pack_into("<I", record, 0x44, zlib.crc32(data) & 0xFFFFFFFF)
        record[0x48:0x58] = hashlib.md5(data).digest()
        name_bytes = name.encode("ascii")
        record[0x58 : 0x58 + len(name_bytes)] = name_bytes
        struct.pack_into("<I", record, 0xFC, zlib.crc32(record[:0xFC]) & 0xFFFFFFFF)
        start = 0x100 + idx * 0x100
        raw_header[start : start + 0x100] = record
        offset += len(data)

    total_size = offset
    struct.pack_into("<IIII", raw_header, 0, MAGIC, header_size, total_size, count)
    raw_header[0x10:0x16] = b"TestPw"
    raw_header[0x20:0x24] = b"OA_E"
    raw_header[0x30:0x34] = b"\x01\x00\x00\x00"
    raw_header[0x48:0x4D] = b"Linux"
    raw_header[0x58:0x5F] = b"Release"
    payload_blob = b"".join(payloads)
    raw_header[0x38:0x48] = hashlib.md5(payload_blob).digest()
    struct.pack_into("<I", raw_header, 0xFC, zlib.crc32(raw_header[:0xFC]) & 0xFFFFFFFF)
    return bytes(raw_header) + payload_blob


def make_synthetic_amac_bundle(components: list[tuple[str, int, bytes]]) -> bytes:
    count = len(components)
    header_size = 0x100 + count * 0x100
    raw_header = bytearray(header_size)
    offset = header_size
    payloads = []
    for idx, (name, type_id, data) in enumerate(components):
        payloads.append(data)
        record = bytearray(0x100)
        struct.pack_into("<III", record, 0, type_id, len(data), offset)
        record[0x1C : 0x1C + len(name)] = name.encode("ascii")
        record[0x3C:0x40] = b"\x01\x00\x00\x00"
        struct.pack_into("<I", record, 0x40, 0)
        record[0x44:0x54] = hashlib.md5(data).digest()
        struct.pack_into("<I", record, 0xFC, zlib.crc32(record[:0xFC]) & 0xFFFFFFFF)
        start = 0x100 + idx * 0x100
        raw_header[start : start + 0x100] = record
        offset += len(data)

    total_size = offset
    raw_header[0:4] = AMAC_MAGIC
    struct.pack_into("<III", raw_header, 4, header_size, total_size, count)
    raw_header[0x10:0x14] = b"\x01\x00\x00\x00"
    payload_blob = b"".join(payloads)
    raw_header[0x14:0x24] = hashlib.md5(payload_blob).digest()
    struct.pack_into("<I", raw_header, 0xFC, zlib.crc32(raw_header[:0xFC]) & 0xFFFFFFFF)
    return bytes(raw_header) + payload_blob


def test_obsbot_bundle_format_roundtrip():
    payloads = [("boot.bin", 1, b"BOOTLOADER"), ("app.bin", 2, b"APPLICATION_DATA")]
    bundle = make_synthetic_obsbot_bundle(payloads)
    meta = parse_bundle(bundle)
    assert meta.product == "TestPw"
    assert meta.channel == "OA_E"
    assert meta.version == "0.0.0.1"
    assert len(meta.entries) == 2
    assert meta.entries[0].name == "boot.bin"
    assert meta.entries[1].name == "app.bin"

    rebuilt = rebuild_bundle(meta, [b"BOOTLOADER", b"APPLICATION_DATA"])
    assert rebuilt == bundle


def test_obsbot_bundle_integrity_rejection():
    bundle = make_synthetic_obsbot_bundle([("boot.bin", 1, b"BOOTLOADER")])
    # Corrupt payload byte
    damaged = bytearray(bundle)
    damaged[-1] ^= 0xFF
    with pytest.raises(FormatError, match="payload CRC32 mismatch"):
        parse_bundle(bytes(damaged))


def test_amac_bundle_format_roundtrip():
    payloads = [("kernel.bin", 1, b"KERNEL_PAYLOAD"), ("rootfs.ubi", 2, b"ROOTFS_PAYLOAD")]
    bundle = make_synthetic_amac_bundle(payloads)
    meta = parse_amac(bundle)
    assert meta.version == "0.0.0.1"
    assert len(meta.entries) == 2
    assert meta.entries[0].name == "kernel.bin"
    assert meta.entries[1].name == "rootfs.ubi"

    rebuilt = rebuild_amac(meta, [b"KERNEL_PAYLOAD", b"ROOTFS_PAYLOAD"])
    assert rebuilt == bundle


async def test_ofrak_obsbot_bundle_lifecycle(ofrak_context: OFRAKContext):
    payloads = [("boot.bin", 1, b"BOOTLOADER_SECTOR"), ("app.bin", 2, b"APPLICATION_SECTOR")]
    bundle_data = make_synthetic_obsbot_bundle(payloads)

    root = await ofrak_context.create_root_resource("obsbot.bin", bundle_data)
    await root.run(ObsbotFirmwareIdentifier)
    assert root.has_tag(ObsbotFirmwareBundle)

    await root.run(ObsbotFirmwareBundleAnalyzer)
    attrs = root.get_attributes(ObsbotFirmwareBundleAttributes)
    assert attrs.product == "TestPw"
    assert attrs.component_count == 2

    await root.run(ObsbotFirmwareUnpacker)
    children = sorted(
        await root.get_children_as_view(ObsbotFirmwareComponent), key=lambda c: c.index
    )
    assert len(children) == 2
    assert children[0].name == "boot.bin"
    assert await children[0].resource.get_data() == b"BOOTLOADER_SECTOR"
    assert children[1].name == "app.bin"
    assert await children[1].resource.get_data() == b"APPLICATION_SECTOR"

    # Modify a component in-place
    new_app = b"APPLICATION_PATCHD"
    await children[1].resource.run(BinaryPatchModifier, BinaryPatchConfig(0, new_app))

    # Repack and verify
    await root.run(ObsbotFirmwarePacker)
    repacked = await root.get_data()
    reparsed = parse_bundle(repacked)
    assert reparsed.entries[1].size == len(new_app)


async def test_ofrak_amac_bundle_lifecycle(ofrak_context: OFRAKContext):
    payloads = [("kernel.bin", 1, b"LINUX_KERNEL_IMAGE"), ("rootfs.ubi", 2, b"ROOTFS_UBI_VOLUME")]
    amac_data = make_synthetic_amac_bundle(payloads)

    root = await ofrak_context.create_root_resource("amac.bin", amac_data)
    await root.run(AmacFirmwareIdentifier)
    assert root.has_tag(AmacFirmwareBundle)

    await root.run(AmacFirmwareBundleAnalyzer)
    attrs = root.get_attributes(AmacFirmwareBundleAttributes)
    assert attrs.component_count == 2

    await root.run(AmacFirmwareUnpacker)
    children = sorted(
        await root.get_children_as_view(ObsbotFirmwareComponent), key=lambda c: c.index
    )
    assert len(children) == 2
    assert children[0].name == "kernel.bin"
    assert await children[0].resource.get_data() == b"LINUX_KERNEL_IMAGE"

    await root.run(AmacFirmwarePacker)
    repacked = await root.get_data()
    assert repacked == amac_data
