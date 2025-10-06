import os
import stat

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource, ResourceFilter
from ofrak.core.cpio import CpioFilesystem, CpioPacker, CpioUnpacker, CpioArchiveType
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from ofrak.core.filesystem import (
    FilesystemEntry,
    File,
    Folder,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
)
from . import ASSETS_DIR

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_CPIO_FILE = "test.cpio"
CPIO_ENTRY_NAME = "hello_cpio_file"


@pytest.mark.skipif_missing_deps([CpioUnpacker, CpioPacker])
class TestCpioUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        cpio_r = await ofrak_context.create_root_resource("root.cpio", b"", (CpioFilesystem,))
        cpio_r.add_view(CpioFilesystem(archive_type=CpioArchiveType.NEW_ASCII))
        await cpio_r.save()
        cpio_v = await cpio_r.view_as(CpioFilesystem)
        # This also tests packing and unpacking a root file
        await cpio_v.add_file(
            path=CPIO_ENTRY_NAME,
            data=INITIAL_DATA,
            file_stat_result=os.stat_result((0o644, 0, 0, 1, 0, 0, 0, 0, 0, 0)),
            file_xattrs=None,
        )
        await cpio_r.pack_recursively()
        return cpio_r

    async def unpack(self, cpio_resource: Resource) -> None:
        await cpio_resource.unpack_recursively()

    async def modify(self, unpacked_cpio_resource: Resource) -> None:
        cpio_v = await unpacked_cpio_resource.view_as(CpioFilesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await cpio_v.get_entry(CPIO_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, cpio_resource: Resource) -> None:
        await cpio_resource.pack_recursively()

    async def verify(self, repacked_cpio_resource: Resource) -> None:
        await repacked_cpio_resource.unpack_recursively()
        cpio_v = await repacked_cpio_resource.view_as(CpioFilesystem)
        child_textfile = await cpio_v.get_entry(CPIO_ENTRY_NAME)
        patched_data = await child_textfile.resource.get_data()
        assert patched_data == EXPECTED_DATA


async def test_character_device(ofrak_context: OFRAKContext):
    cpio_r = await ofrak_context.create_root_resource("character.cpio", b"", (CpioFilesystem,))
    cpio_r.add_view(CpioFilesystem(archive_type=CpioArchiveType.NEW_ASCII))
    await cpio_r.save()
    cpio_v = await cpio_r.view_as(CpioFilesystem)
    chardev = CharacterDevice(
        name="chardev",
        stat=os.stat_result((0o20644, 0, 0, 1, 0, 0, 0, 0, 0, 0)),
        xattrs=None,
    )
    await cpio_v.add_special_file_entry("chardev", chardev)
    await cpio_r.pack_recursively()
    cpio_data = await cpio_r.get_data()

    root_resource = await ofrak_context.create_root_resource(
        "character2.cpio", cpio_data, (CpioFilesystem,)
    )

    await root_resource.unpack()

    children = list(await root_resource.get_children())
    assert len(children) > 0, "Should have unpacked children"


async def test_round_trip_metadata_preservation(ofrak_context: OFRAKContext):
    from ofrak.core.filesystem import FilesystemEntry
    from ofrak.service.resource_service_i import ResourceFilter

    # First unpack
    root1 = await ofrak_context.create_root_resource_from_file(
        os.path.join(ASSETS_DIR, "tinycore.cpio")
    )
    await root1.unpack()

    # Capture all metadata from first unpack
    metadata1 = {}
    descendants1 = await root1.get_descendants(r_filter=ResourceFilter(tags=(FilesystemEntry,)))
    for entry_resource in descendants1:
        entry = await entry_resource.view_as(FilesystemEntry)
        path = await entry.get_path()
        if entry.stat:
            metadata1[path] = {
                "mode": entry.stat.st_mode,
                "nlink": entry.stat.st_nlink,
                "uid": entry.stat.st_uid,
                "gid": entry.stat.st_gid,
                "size": entry.stat.st_size,
                "atime": entry.stat.st_atime,
                "mtime": entry.stat.st_mtime,
                "ctime": entry.stat.st_ctime,
                "xattrs": dict(entry.xattrs) if entry.xattrs else {},
            }

    # Repack
    await root1.pack()
    repacked_data = await root1.get_data()

    # Second unpack
    root2 = await ofrak_context.create_root_resource(
        name="repacked_core_tinycore", data=repacked_data
    )
    await root2.unpack()

    # Capture metadata from second unpack
    metadata2 = {}
    descendants2 = await root2.get_descendants(r_filter=ResourceFilter(tags=(FilesystemEntry,)))
    for entry_resource in descendants2:
        entry = await entry_resource.view_as(FilesystemEntry)
        path = await entry.get_path()
        if entry.stat:
            metadata2[path] = {
                "mode": entry.stat.st_mode,
                "nlink": entry.stat.st_nlink,
                "uid": entry.stat.st_uid,
                "gid": entry.stat.st_gid,
                "size": entry.stat.st_size,
                "atime": entry.stat.st_atime,
                "mtime": entry.stat.st_mtime,
                "ctime": entry.stat.st_ctime,
                "xattrs": dict(entry.xattrs) if entry.xattrs else {},
            }

    # Compare metadata - key attributes must match
    mismatches = []
    for path in metadata1:
        if path not in metadata2:
            mismatches.append(f"Missing in second unpack: {path}")
            continue

        m1 = metadata1[path]
        m2 = metadata2[path]

        # Check if this is a symlink using stat module
        is_symlink = stat.S_ISLNK(m1["mode"])

        # For symlinks, skip size check - libarchive CPIO writer doesn't preserve symlink size
        # This is a known limitation of libarchive's add_file_from_memory for CPIO symlinks
        keys_to_check = ["mode", "nlink", "uid", "gid", "atime", "mtime", "ctime", "xattrs"]
        if not is_symlink:
            keys_to_check.append("size")

        for key in keys_to_check:
            if m1[key] != m2[key]:
                mismatches.append(f"{path}: {key} changed from {m1[key]} to {m2[key]}")

    assert len(mismatches) == 0, f"Metadata not preserved: {mismatches}"


async def test_special_file_types(ofrak_context: OFRAKContext):
    """Test that various file types are correctly handled."""

    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(ASSETS_DIR, "tinycore.cpio")
    )
    await root.unpack()

    descendants = await root.get_descendants(r_filter=ResourceFilter(tags=(FilesystemEntry,)))

    found_regular_file = False
    found_directory = False
    found_symlink = False
    found_character_device = False
    found_block_device = False

    for entry_resource in descendants:
        entry = await entry_resource.view_as(FilesystemEntry)
        path = await entry.get_path()

        if stat.S_ISREG(entry.stat.st_mode):
            if not found_regular_file and entry_resource.has_tag(File):
                found_regular_file = True
                # Verify we can read data from regular files
                if entry.stat.st_size > 0:
                    data = await entry_resource.get_data()
                    assert len(data) == entry.stat.st_size
        elif stat.S_ISDIR(entry.stat.st_mode):
            if not found_directory and entry_resource.has_tag(Folder):
                found_directory = True
        elif stat.S_ISLNK(entry.stat.st_mode):
            if not found_symlink and entry_resource.has_tag(SymbolicLink):
                symlink = await entry_resource.view_as(SymbolicLink)
                # Verify symlink has a target path
                assert symlink.source_path is not None
                assert len(symlink.source_path) > 0
                found_symlink = True
        elif stat.S_ISCHR(entry.stat.st_mode):
            if not found_character_device and entry_resource.has_tag(CharacterDevice):
                found_character_device = True
        elif stat.S_ISBLK(entry.stat.st_mode):
            if not found_block_device and entry_resource.has_tag(BlockDevice):
                found_block_device = True

        if (
            found_regular_file
            and found_directory
            and found_symlink
            and found_character_device
            and found_block_device
        ):
            break

    # Verify we found all expected file types
    assert found_regular_file, "Should find at least one regular file"
    assert found_directory, "Should find at least one directory"
    assert found_symlink, "Should find at least one symlink"
    assert found_character_device, "Should find at least one character device"
    assert found_block_device, "Should find at least one block device"


@pytest.mark.parametrize(
    "archive_type",
    [
        CpioArchiveType.OLD_ASCII,
        CpioArchiveType.NEW_ASCII,
    ],
)
async def test_cpio_type_preservation(ofrak_context: OFRAKContext, archive_type: CpioArchiveType):
    """
    Test that CPIO files of different CpioArchiveType can be created, packed, unpacked, and preserves its type.

    Some CPIO types are known to not preserve the archive type. It is a known limitation of libarchive, which manpage says:
    > The libarchive(3) library can read most tar archives. However, it only writes POSIX-standard ''ustar'' and ''pax interchange'' formats.

    The following types were removed from this test because the archive type is not preserved:
    - CpioArchiveType.BINARY
    - CpioArchiveType.CRC_ASCII
    - CpioArchiveType.TAR
    - CpioArchiveType.HPBIN
    - CpioArchiveType.HPODC
    - CpioArchiveType.USTAR (this type of file created with libarchive is then recognized as a POSIX tar archive by magic)
    """

    # Create a CPIO archive with the specified type
    cpio_r = await ofrak_context.create_root_resource(
        f"test_{archive_type.value}.cpio", b"", (CpioFilesystem,)
    )
    cpio_r.add_view(CpioFilesystem(archive_type=archive_type))
    await cpio_r.save()

    filename = "test_file.txt"
    file_content = b"test content for archive type preservation"
    # Add a simple file to the archive
    cpio_v = await cpio_r.view_as(CpioFilesystem)
    await cpio_v.add_file(
        path=filename,
        data=file_content,
        file_stat_result=os.stat_result((0o644, 0, 0, 1, 0, 0, 0, 0, 0, 0)),
        file_xattrs=None,
    )

    # Pack the archive
    await cpio_r.pack_recursively()
    packed_data = await cpio_r.get_data()

    # Create a new resource from the packed data
    new_cpio_r = await ofrak_context.create_root_resource(
        name=f"repacked_{archive_type.value}.cpio", data=packed_data
    )

    # Unpack and verify the archive type is preserved
    await new_cpio_r.unpack()
    new_cpio_v = await new_cpio_r.view_as(CpioFilesystem)

    # Verify the archive type is preserved
    assert (
        new_cpio_v.archive_type == archive_type
    ), f"Archive type not preserved: expected {archive_type}, got {new_cpio_v.archive_type}"

    # Verify the file content is preserved
    child_file = await new_cpio_v.get_entry(filename)
    file_data = await child_file.resource.get_data()
    assert file_data == file_content
