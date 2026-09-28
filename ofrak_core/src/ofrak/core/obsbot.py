from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import Sequence

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core import GenericBinary
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak_type.range import Range

MAGIC = 0xAB20EC98
AMAC_MAGIC = b"AMAC"
MAIN_HEADER_SIZE = 0x100
ENTRY_SIZE = 0x100
CRC_OFFSET = 0xFC


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class ComponentRecord:
    index: int
    type_id: int
    offset: int
    size: int
    version: str
    flags: int
    payload_crc32: int | None
    payload_md5: bytes
    name: str
    raw: bytes


@dataclass(frozen=True)
class BundleMetadata:
    header_size: int
    total_size: int
    product: str
    channel: str
    version: str
    platform: str
    release: str
    payload_md5: bytes
    entries: tuple[ComponentRecord, ...]
    raw_header: bytes


@dataclass(frozen=True)
class AmacMetadata:
    header_size: int
    total_size: int
    version: str
    payload_md5: bytes
    entries: tuple[ComponentRecord, ...]
    raw_header: bytes


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _cstr(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii")


def _version(data: bytes) -> str:
    return ".".join(str(part) for part in reversed(data))


def _parse_entries(
    data: bytes,
    header_size: int,
    count: int,
    name_offset: int,
    payload_crc_offset: int | None,
    payload_md5_offset: int,
    verify_integrity: bool,
) -> tuple[ComponentRecord, ...]:
    entries = []
    expected_offset = header_size
    for index in range(count):
        start = MAIN_HEADER_SIZE + index * ENTRY_SIZE
        record = data[start : start + ENTRY_SIZE]
        type_id, size, offset = struct.unpack_from("<III", record)
        if offset != expected_offset or size > len(data) - offset:
            raise FormatError(f"component {index} has invalid span 0x{offset:x}+0x{size:x}")
        if (
            verify_integrity
            and _crc32(record[:CRC_OFFSET]) != struct.unpack_from("<I", record, CRC_OFFSET)[0]
        ):
            raise FormatError(f"component {index} record CRC32 mismatch")
        payload = data[offset : offset + size]
        payload_crc32 = (
            struct.unpack_from("<I", record, payload_crc_offset)[0]
            if payload_crc_offset is not None
            else None
        )
        payload_md5 = record[payload_md5_offset : payload_md5_offset + 16]
        if verify_integrity and payload_crc32 is not None and _crc32(payload) != payload_crc32:
            raise FormatError(f"component {index} payload CRC32 mismatch")
        if verify_integrity and hashlib.md5(payload, usedforsecurity=False).digest() != payload_md5:
            raise FormatError(f"component {index} payload MD5 mismatch")
        name = _cstr(
            record[name_offset:0x3C] if name_offset < 0x3C else record[name_offset:CRC_OFFSET]
        )
        if not name or name != name.rsplit("/", 1)[-1]:
            raise FormatError(f"component {index} has unsafe name {name!r}")
        entries.append(
            ComponentRecord(
                index,
                type_id,
                offset,
                size,
                _version(record[0x3C:0x40]),
                struct.unpack_from("<I", record, 0x40)[0],
                payload_crc32,
                payload_md5,
                name,
                record,
            )
        )
        expected_offset += size
    if expected_offset != len(data):
        raise FormatError(f"component spans end at 0x{expected_offset:x}, not EOF")
    return tuple(entries)


def parse_bundle(data: bytes, verify_integrity: bool = True) -> BundleMetadata:
    if len(data) < MAIN_HEADER_SIZE:
        raise FormatError("bundle is shorter than its main header")
    magic, header_size, total_size, count = struct.unpack_from("<IIII", data)
    if magic != MAGIC:
        raise FormatError(f"bad magic: 0x{magic:08x}")
    if header_size < MAIN_HEADER_SIZE or header_size % ENTRY_SIZE:
        raise FormatError(f"invalid header size: 0x{header_size:x}")
    if count > (header_size - MAIN_HEADER_SIZE) // ENTRY_SIZE:
        raise FormatError("component table exceeds header")
    if total_size != len(data):
        raise FormatError(f"declared size {total_size} != actual size {len(data)}")
    if (
        verify_integrity
        and _crc32(data[:CRC_OFFSET]) != struct.unpack_from("<I", data, CRC_OFFSET)[0]
    ):
        raise FormatError("package header CRC32 mismatch")

    entries = _parse_entries(data, header_size, count, 0x58, 0x44, 0x48, verify_integrity)
    payload_md5 = data[0x38:0x48]
    if (
        verify_integrity
        and hashlib.md5(data[header_size:], usedforsecurity=False).digest() != payload_md5
    ):
        raise FormatError("package payload MD5 mismatch")
    return BundleMetadata(
        header_size,
        total_size,
        _cstr(data[0x10:0x20]),
        _cstr(data[0x20:0x30]),
        _version(data[0x30:0x34]),
        _cstr(data[0x48:0x58]),
        _cstr(data[0x58:0x68]),
        payload_md5,
        entries,
        data[:header_size],
    )


def rebuild_bundle(metadata: BundleMetadata, payloads: Sequence[bytes]) -> bytes:
    if len(payloads) != len(metadata.entries):
        raise FormatError("payload count does not match component table")
    header = bytearray(metadata.raw_header)
    offset = metadata.header_size
    for entry, payload in zip(metadata.entries, payloads, strict=True):
        record = bytearray(entry.raw)
        struct.pack_into("<III", record, 0, entry.type_id, len(payload), offset)
        struct.pack_into("<I", record, 0x44, _crc32(payload))
        record[0x48:0x58] = hashlib.md5(payload, usedforsecurity=False).digest()
        struct.pack_into("<I", record, CRC_OFFSET, _crc32(record[:CRC_OFFSET]))
        start = MAIN_HEADER_SIZE + entry.index * ENTRY_SIZE
        header[start : start + ENTRY_SIZE] = record
        offset += len(payload)
    payload_blob = b"".join(payloads)
    struct.pack_into("<II", header, 8, offset, len(payloads))
    header[0x38:0x48] = hashlib.md5(payload_blob, usedforsecurity=False).digest()
    struct.pack_into("<I", header, CRC_OFFSET, _crc32(header[:CRC_OFFSET]))
    return bytes(header) + payload_blob


def parse_amac(data: bytes, verify_integrity: bool = True) -> AmacMetadata:
    if len(data) < MAIN_HEADER_SIZE or data[:4] != AMAC_MAGIC:
        raise FormatError("bad AMAC magic or short header")
    header_size, total_size, count = struct.unpack_from("<III", data, 4)
    if header_size < MAIN_HEADER_SIZE or header_size % ENTRY_SIZE:
        raise FormatError(f"invalid AMAC header size: 0x{header_size:x}")
    if count > (header_size - MAIN_HEADER_SIZE) // ENTRY_SIZE or total_size != len(data):
        raise FormatError("invalid AMAC count or total size")
    if (
        verify_integrity
        and _crc32(data[:CRC_OFFSET]) != struct.unpack_from("<I", data, CRC_OFFSET)[0]
    ):
        raise FormatError("AMAC header CRC32 mismatch")
    entries = _parse_entries(data, header_size, count, 0x1C, None, 0x44, verify_integrity)
    payload_md5 = data[0x14:0x24]
    if (
        verify_integrity
        and hashlib.md5(data[header_size:], usedforsecurity=False).digest() != payload_md5
    ):
        raise FormatError("AMAC payload MD5 mismatch")
    return AmacMetadata(
        header_size,
        total_size,
        _version(data[0x10:0x14]),
        payload_md5,
        entries,
        data[:header_size],
    )


def rebuild_amac(metadata: AmacMetadata, payloads: Sequence[bytes]) -> bytes:
    if len(payloads) != len(metadata.entries):
        raise FormatError("payload count does not match AMAC table")
    header = bytearray(metadata.raw_header)
    offset = metadata.header_size
    for entry, payload in zip(metadata.entries, payloads, strict=True):
        record = bytearray(entry.raw)
        struct.pack_into("<III", record, 0, entry.type_id, len(payload), offset)
        record[0x44:0x54] = hashlib.md5(payload, usedforsecurity=False).digest()
        struct.pack_into("<I", record, CRC_OFFSET, _crc32(record[:CRC_OFFSET]))
        start = MAIN_HEADER_SIZE + entry.index * ENTRY_SIZE
        header[start : start + ENTRY_SIZE] = record
        offset += len(payload)
    payload_blob = b"".join(payloads)
    struct.pack_into("<II", header, 8, offset, len(payloads))
    header[0x14:0x24] = hashlib.md5(payload_blob, usedforsecurity=False).digest()
    struct.pack_into("<I", header, CRC_OFFSET, _crc32(header[:CRC_OFFSET]))
    return bytes(header) + payload_blob


@dataclass
class ObsbotFirmwareBundle(GenericBinary):
    pass


@dataclass
class ObsbotFirmwareComponent(GenericBinary):
    index: int
    type_id: int
    offset: int
    size: int
    version: str
    name: str
    flags: int


@dataclass
class AmacFirmwareBundle(GenericBinary):
    pass


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ObsbotFirmwareBundleAttributes(ResourceAttributes):
    product: str
    channel: str
    version: str
    platform: str
    release: str
    header_size: int
    total_size: int
    component_count: int
    payload_md5: str


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AmacFirmwareBundleAttributes(ResourceAttributes):
    version: str
    header_size: int
    total_size: int
    component_count: int
    payload_md5: str


def _attributes(metadata: BundleMetadata) -> ObsbotFirmwareBundleAttributes:
    return ObsbotFirmwareBundleAttributes(
        metadata.product,
        metadata.channel,
        metadata.version,
        metadata.platform,
        metadata.release,
        metadata.header_size,
        metadata.total_size,
        len(metadata.entries),
        metadata.payload_md5.hex(),
    )


class ObsbotFirmwareIdentifier(Identifier[None]):
    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config=None) -> None:
        if await resource.get_data(Range(0, 4)) == MAGIC.to_bytes(4, "little"):
            resource.add_tag(ObsbotFirmwareBundle)


class AmacFirmwareIdentifier(Identifier[None]):
    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config=None) -> None:
        if await resource.get_data(Range(0, 4)) == AMAC_MAGIC:
            resource.add_tag(AmacFirmwareBundle)


class ObsbotFirmwareBundleAnalyzer(Analyzer[None, ObsbotFirmwareBundleAttributes]):
    targets = (ObsbotFirmwareBundle,)
    outputs = (ObsbotFirmwareBundleAttributes,)

    async def analyze(self, resource: Resource, config=None) -> ObsbotFirmwareBundleAttributes:
        return _attributes(parse_bundle(await resource.get_data()))


class AmacFirmwareBundleAnalyzer(Analyzer[None, AmacFirmwareBundleAttributes]):
    targets = (AmacFirmwareBundle,)
    outputs = (AmacFirmwareBundleAttributes,)

    async def analyze(self, resource: Resource, config=None) -> AmacFirmwareBundleAttributes:
        metadata = parse_amac(await resource.get_data())
        return AmacFirmwareBundleAttributes(
            metadata.version,
            metadata.header_size,
            metadata.total_size,
            len(metadata.entries),
            metadata.payload_md5.hex(),
        )


class ObsbotFirmwareUnpacker(Unpacker[None]):
    targets = (ObsbotFirmwareBundle,)
    children = (ObsbotFirmwareComponent,)

    async def unpack(self, resource: Resource, config=None) -> None:
        metadata = parse_bundle(await resource.get_data())
        resource.add_attributes(_attributes(metadata))
        for entry in metadata.entries:
            await resource.create_child_from_view(
                ObsbotFirmwareComponent(
                    entry.index,
                    entry.type_id,
                    entry.offset,
                    entry.size,
                    entry.version,
                    entry.name,
                    entry.flags,
                ),
                data_range=Range.from_size(entry.offset, entry.size),
            )


class ObsbotFirmwarePacker(Packer[None]):
    targets = (ObsbotFirmwareBundle,)

    async def pack(self, resource: Resource, config=None) -> None:
        current = await resource.get_data()
        metadata = parse_bundle(current, verify_integrity=False)
        child_ranges = []
        for child in await resource.get_children():
            r = await child.get_data_range_within_parent()
            child_ranges.append((r.start, child))
        child_ranges.sort(key=lambda item: item[0])
        children = [child for _, child in child_ranges]
        if len(children) != len(metadata.entries):
            raise ValueError("component child count does not match bundle table")
        payloads = [await child.get_data() for child in children]
        rebuilt = rebuild_bundle(metadata, payloads)
        resource.queue_patch(Range(0, len(current)), rebuilt)
        resource.add_attributes(_attributes(parse_bundle(rebuilt)))


class AmacFirmwareUnpacker(Unpacker[None]):
    targets = (AmacFirmwareBundle,)
    children = (ObsbotFirmwareComponent,)

    async def unpack(self, resource: Resource, config=None) -> None:
        metadata = parse_amac(await resource.get_data())
        for entry in metadata.entries:
            await resource.create_child_from_view(
                ObsbotFirmwareComponent(
                    entry.index,
                    entry.type_id,
                    entry.offset,
                    entry.size,
                    entry.version,
                    entry.name,
                    entry.flags,
                ),
                data_range=Range.from_size(entry.offset, entry.size),
            )


class AmacFirmwarePacker(Packer[None]):
    targets = (AmacFirmwareBundle,)

    async def pack(self, resource: Resource, config=None) -> None:
        current = await resource.get_data()
        metadata = parse_amac(current, verify_integrity=False)
        child_ranges = []
        for child in await resource.get_children():
            r = await child.get_data_range_within_parent()
            child_ranges.append((r.start, child))
        child_ranges.sort(key=lambda item: item[0])
        children = [child for _, child in child_ranges]
        if len(children) != len(metadata.entries):
            raise ValueError("component child count does not match AMAC table")
        payloads = [await child.get_data() for child in children]
        rebuilt = rebuild_amac(metadata, payloads)
        resource.queue_patch(Range(0, len(current)), rebuilt)
