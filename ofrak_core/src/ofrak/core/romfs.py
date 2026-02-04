"""
RomFS filesystem components.

RomFS (ROM filesystem) is a simple, space-efficient, read-only filesystem commonly used in
embedded Linux systems, particularly for initial ramdisks and firmware images. The format stores
files with minimal overhead using a straightforward linked-list structure with 16-byte alignment.

RomfsUnpacker parses the RomFS binary format in pure Python, extracting regular files,
directories, and symbolic links.

RomfsPacker uses the ``genromfs`` tool to repack a filesystem tree into a RomFS image.
"""

import asyncio
import logging
import os
import struct
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.magic import MagicDescriptionPattern, RawMagicPattern
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

ROMFS_MAGIC = b"-rom1fs-"

# RomFS file entry types
_ROMFS_TYPE_HARDLINK = 0
_ROMFS_TYPE_DIRECTORY = 1
_ROMFS_TYPE_REGULAR = 2
_ROMFS_TYPE_SYMLINK = 3
_ROMFS_TYPE_BLOCKDEV = 4
_ROMFS_TYPE_CHARDEV = 5
_ROMFS_TYPE_SOCKET = 6
_ROMFS_TYPE_FIFO = 7

GENROMFS = ComponentExternalTool(
    "genromfs",
    "https://romfs.sourceforge.net/",
    install_check_arg="-h",
    apt_package="genromfs",
    brew_package="genromfs",
)


@dataclass
class RomfsFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a RomFS format.
    """


class RomfsUnpacker(Unpacker[None]):
    """
    Extracts files and directories from RomFS read-only filesystems, commonly used in embedded
    Linux systems for initial ramdisks and firmware images. RomFS is a compact, read-only format
    that stores files with minimal overhead. The unpacker parses the binary format directly in
    Python, extracting regular files, directories, and symbolic links while preserving the
    directory hierarchy.
    """

    targets = (RomfsFilesystem,)
    children = (File, Folder, SpecialFileType)

    async def unpack(self, resource: Resource, config=None):
        data = await resource.get_data()

        with tempfile.TemporaryDirectory() as temp_dir:
            _extract_romfs(data, temp_dir)

            romfs_view = await resource.view_as(RomfsFilesystem)
            await romfs_view.initialize_from_disk(temp_dir)


class RomfsPacker(Packer[None]):
    """
    Packages files into a RomFS read-only filesystem image using the ``genromfs`` tool. Use after
    modifying extracted RomFS contents to recreate firmware images or embedded filesystem images.
    """

    targets = (RomfsFilesystem,)
    external_dependencies = (GENROMFS,)

    async def pack(self, resource: Resource, config=None):
        romfs_view: RomfsFilesystem = await resource.view_as(RomfsFilesystem)
        temp_flush_dir = await romfs_view.flush_to_disk()

        with tempfile.NamedTemporaryFile(
            suffix=".romfs", mode="rb", delete_on_close=False
        ) as temp:
            temp.close()
            cmd = [
                "genromfs",
                "-f",
                temp.name,
                "-d",
                temp_flush_dir,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode:
                raise CalledProcessError(
                    returncode=proc.returncode,
                    cmd=cmd,
                    output=stdout,
                    stderr=stderr,
                )

            with open(temp.name, "rb") as fh:
                new_data = fh.read()

            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


def _align16(offset: int) -> int:
    """Align offset up to the next 16-byte boundary."""
    return (offset + 15) & ~15


def _extract_romfs(data: bytes, output_dir: str) -> None:
    """
    Parse a RomFS image and extract its contents to output_dir.

    :param data: Raw bytes of the RomFS image
    :param output_dir: Directory to extract files into
    :raises ValueError: If the data is not a valid RomFS image
    """
    if len(data) < 16 or data[:8] != ROMFS_MAGIC:
        raise ValueError("Not a valid RomFS image: bad magic")

    # Volume name starts at offset 16, null-terminated, padded to 16-byte boundary
    vol_name_end = data.index(b"\x00", 16)

    # First file entry (root directory ".") starts after the padded volume name
    root_offset = _align16(vol_name_end + 1)

    if root_offset + 16 > len(data):
        return

    # Parse root directory entry
    next_and_type = struct.unpack_from(">I", data, root_offset)[0]
    spec_info = struct.unpack_from(">I", data, root_offset + 4)[0]
    file_type = next_and_type & 0x7

    if file_type != _ROMFS_TYPE_DIRECTORY:
        raise ValueError(
            f"Root entry is not a directory (type={file_type}), invalid RomFS image"
        )

    # spec_info points to the first entry in the root directory, which is the root "."
    # entry itself. We need to iterate siblings starting from there, skipping "." and "..".
    if spec_info != 0:
        _extract_entries(data, spec_info, output_dir, set())


def _extract_entries(
    data: bytes, offset: int, parent_dir: str, visited: set
) -> None:
    """
    Extract all sibling entries starting at the given offset, recursing into directories.

    :param data: Raw bytes of the RomFS image
    :param offset: Offset of the first sibling entry
    :param parent_dir: Directory on disk to extract into
    :param visited: Set of already-visited offsets to prevent cycles
    """
    while offset != 0:
        if offset in visited:
            break
        visited.add(offset)

        if offset + 16 > len(data):
            LOGGER.warning(
                "RomFS entry at offset 0x%x extends beyond image boundary", offset
            )
            break

        next_and_type = struct.unpack_from(">I", data, offset)[0]
        spec_info = struct.unpack_from(">I", data, offset + 4)[0]
        size = struct.unpack_from(">I", data, offset + 8)[0]

        file_type = next_and_type & 0x7
        next_offset = next_and_type & ~0xF

        # Read the entry name (null-terminated, starts at offset+16)
        name_start = offset + 16
        try:
            name_end = data.index(b"\x00", name_start)
        except ValueError:
            LOGGER.warning(
                "RomFS entry at offset 0x%x has unterminated name", offset
            )
            break

        name = data[name_start:name_end].decode("ascii", errors="replace")

        # Data starts after the padded name
        data_start = _align16(name_end + 1)

        # Skip "." and ".." entries
        if name in (".", ".."):
            offset = next_offset
            continue

        entry_path = os.path.join(parent_dir, name)

        if file_type == _ROMFS_TYPE_DIRECTORY:
            os.makedirs(entry_path, exist_ok=True)
            if spec_info != 0:
                _extract_entries(data, spec_info, entry_path, visited)

        elif file_type == _ROMFS_TYPE_REGULAR:
            file_data = data[data_start : data_start + size]
            with open(entry_path, "wb") as f:
                f.write(file_data)

        elif file_type == _ROMFS_TYPE_SYMLINK:
            link_target = data[data_start : data_start + size]
            link_target_str = link_target.rstrip(b"\x00").decode(
                "ascii", errors="replace"
            )
            os.symlink(link_target_str, entry_path)

        elif file_type == _ROMFS_TYPE_HARDLINK:
            # Hard links in RomFS point to another file entry by offset.
            # Skip "." and ".." hard links (already handled above).
            pass

        else:
            LOGGER.warning(
                "Skipping unsupported RomFS entry type %d for '%s'",
                file_type,
                name,
            )

        offset = next_offset


def _match_romfs_magic(data: bytes) -> bool:
    """Check for the RomFS magic bytes ``-rom1fs-``."""
    if len(data) < 8:
        return False
    return data[:8] == ROMFS_MAGIC


RawMagicPattern.register(RomfsFilesystem, _match_romfs_magic)
MagicDescriptionPattern.register(
    RomfsFilesystem, lambda s: s.startswith("romfs filesystem")
)
