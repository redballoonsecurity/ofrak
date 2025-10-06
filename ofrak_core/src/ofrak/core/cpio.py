import logging
import os
import stat
from dataclasses import dataclass
from enum import Enum

from ofrak.component.analyzer import Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import (
    File,
    Folder,
    FilesystemRoot,
    SpecialFileType,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
    FIFOPipe,
)
from ofrak.core.magic import MagicMimePattern, MagicDescriptionPattern, Magic
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.range import Range
from ofrak.core.filesystem import FilesystemEntry

# The libarchive binary is a requirement for the libarchive-c python bindings to work
try:
    import libarchive

    LIBARCHIVE_INSTALLED = True
except (AttributeError, OSError, TypeError):
    # Linux throws an AttributeError, MacOS an OSError, Windows a TypeError
    LIBARCHIVE_INSTALLED = False


class LibarchiveTool(ComponentExternalTool):
    def __init__(self):
        super().__init__(
            "libarchive",
            "https://www.libarchive.org/",
            install_check_arg="",
            apt_package="libarchive",
            brew_package="libarchive",
            choco_package="libarchive",
        )

    async def is_tool_installed(self) -> bool:
        return LIBARCHIVE_INSTALLED


LIBARCHIVE_TOOL: LibarchiveTool = LibarchiveTool()

LOGGER = logging.getLogger(__name__)


class CpioArchiveType(Enum):
    """
    CPIO has several unrelated, incompatible variants.
    They're described in the man page:
    https://linux.die.net/man/1/cpio
    """

    BINARY = "bin"
    OLD_ASCII = "odc"
    NEW_ASCII = "newc"
    CRC_ASCII = "crc"
    TAR = "tar"
    USTAR = "ustar"
    HPBIN = "hpbin"
    HPODC = "hpodc"


@dataclass
class CpioFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a CPIO archive.
    """

    archive_type: CpioArchiveType


class CpioFilesystemAnalyzer(Analyzer[None, CpioFilesystem]):
    targets = (CpioFilesystem,)
    outputs = (CpioFilesystem,)

    async def analyze(self, resource: Resource, config=None) -> CpioFilesystem:
        _magic = await resource.analyze(Magic)
        magic_description = _magic.descriptor
        if magic_description.startswith("ASCII cpio archive (SVR4 with no CRC)"):
            archive_type = CpioArchiveType.NEW_ASCII
        elif magic_description.startswith("ASCII cpio archive (pre-SVR4 or odc)"):
            archive_type = CpioArchiveType.OLD_ASCII
        elif magic_description.startswith("ASCII cpio archive (SVR4 with CRC)"):
            archive_type = CpioArchiveType.CRC_ASCII
        elif magic_description.startswith("cpio archive"):
            archive_type = CpioArchiveType.BINARY
        else:
            raise NotImplementedError(
                f"Please add support for CPIO archive type {magic_description}"
            )

        return CpioFilesystem(archive_type)


def _libarchive_entry_to_stat_result(entry) -> os.stat_result:
    return os.stat_result(
        (
            entry.mode,  # st_mode (complete mode: file type + permission bits)
            0,  # st_ino (not preserved in CPIO)
            0,  # st_dev (not preserved)
            1,  # st_nlink (default, it looks like we can't get this from libarchive)
            entry.uid,  # st_uid
            entry.gid,  # st_gid
            entry.size,  # st_size
            int(entry.atime) if entry.atime else 0,  # st_atime
            int(entry.mtime) if entry.mtime else 0,  # st_mtime
            int(entry.ctime) if entry.ctime else 0,  # st_ctime
        )
    )


class CpioUnpacker(Unpacker[None]):
    """
    Unpack a CPIO archive using libarchive.
    """

    targets = (CpioFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (LIBARCHIVE_TOOL,)

    async def unpack(self, resource: Resource, config=None):
        cpio_v = await resource.view_as(CpioFilesystem)
        resource_data = await cpio_v.resource.get_data()

        with libarchive.memory_reader(resource_data) as archive:
            for entry in archive:
                if entry.pathname in (".", "./"):
                    continue

                # remove leading ./
                path = entry.pathname.lstrip("./")
                if not path:
                    continue

                entry_stat = _libarchive_entry_to_stat_result(entry)

                xattrs = {}
                if hasattr(entry, "xattr"):
                    for xattr_name in entry.xattr.keys():
                        xattrs[xattr_name] = entry.xattr.get(xattr_name)

                filetype = entry.filetype

                if stat.S_ISREG(filetype):
                    data = b"".join(entry.get_blocks())
                    await cpio_v.add_file(path, data, entry_stat, xattrs or None)
                elif stat.S_ISDIR(filetype):
                    await cpio_v.add_folder(path, entry_stat, xattrs or None)
                elif stat.S_ISLNK(filetype):
                    linkpath = entry.linkpath or ""
                    symlink = SymbolicLink(
                        name=path, stat=entry_stat, xattrs=xattrs or None, source_path=linkpath
                    )
                    await cpio_v.add_special_file_entry(path, symlink)
                elif stat.S_ISCHR(filetype):
                    chardev = CharacterDevice(name=path, stat=entry_stat, xattrs=xattrs or None)
                    await cpio_v.add_special_file_entry(path, chardev)
                elif stat.S_ISBLK(filetype):
                    blockdev = BlockDevice(name=path, stat=entry_stat, xattrs=xattrs or None)
                    await cpio_v.add_special_file_entry(path, blockdev)
                elif stat.S_ISFIFO(filetype):
                    fifo = FIFOPipe(name=path, stat=entry_stat, xattrs=xattrs or None)
                    await cpio_v.add_special_file_entry(path, fifo)
                else:
                    raise NotImplementedError(f"Unsupported file type: {oct(filetype)}")


def _ofrak_tags_to_filetype(resource) -> int:
    if resource.has_tag(File):
        return stat.S_IFREG
    elif resource.has_tag(Folder):
        return stat.S_IFDIR
    elif resource.has_tag(SymbolicLink):
        return stat.S_IFLNK
    elif resource.has_tag(CharacterDevice):
        return stat.S_IFCHR
    elif resource.has_tag(BlockDevice):
        return stat.S_IFBLK
    elif resource.has_tag(FIFOPipe):
        return stat.S_IFIFO
    else:
        raise ValueError("Unknown file type")


def _get_libarchive_format(archive_type: CpioArchiveType) -> str:
    """
    Note: libarchive supports reading many CPIO variants but only supports
    writing a subset. We map to the closest supported write format.
    Available write formats: 'cpio' (generic), 'cpio_newc' (SVR4 newc)
    """
    format_map = {
        CpioArchiveType.NEW_ASCII: "cpio_newc",
        CpioArchiveType.OLD_ASCII: "cpio",
        CpioArchiveType.CRC_ASCII: "cpio_newc",
        CpioArchiveType.BINARY: "cpio",
        CpioArchiveType.TAR: "cpio",
        CpioArchiveType.USTAR: "ustar",
        CpioArchiveType.HPBIN: "cpio",
        CpioArchiveType.HPODC: "cpio",
    }
    return format_map.get(archive_type, "cpio_newc")


class CpioPacker(Packer[None]):
    """
    Pack files into a CPIO archive using libarchive.
    """

    targets = (CpioFilesystem,)
    external_dependencies = (LIBARCHIVE_TOOL,)

    async def pack(self, resource: Resource, config=None):
        cpio_v: CpioFilesystem = await resource.view_as(CpioFilesystem)

        format_str = _get_libarchive_format(cpio_v.archive_type)

        entries = await resource.get_descendants(r_filter=ResourceFilter(tags=(FilesystemEntry,)))

        # Sort entries by path (parents before children)
        entry_list = []
        for entry_resource in entries:
            entry = await entry_resource.view_as(FilesystemEntry)
            path = await entry.get_path()
            entry_list.append((path, entry, entry_resource))

        entry_list.sort(key=lambda x: x[0])

        # custom_writer calls our write_func with chunks of data
        packed_chunks = []

        def write_func(data):
            packed_chunks.append(bytes(data))
            return len(data)

        with libarchive.custom_writer(write_func, format_str) as archive:
            for path, entry, entry_resource in entry_list:
                entry_stat = entry.stat
                if not entry_stat:
                    # Create default stat if missing
                    entry_stat = os.stat_result((0o644, 0, 0, 1, 0, 0, 0, 0, 0, 0))

                xattrs = entry.xattrs or {}

                filetype = _ofrak_tags_to_filetype(entry_resource)

                linkpath = None
                is_symlink = entry_resource.has_tag(SymbolicLink)
                if is_symlink:
                    symlink_view = await entry_resource.view_as(SymbolicLink)
                    linkpath = symlink_view.source_path

                # Get data only for regular files (not symlinks, directories, or special files)
                data = b""
                entry_size = 0
                if entry_resource.has_tag(File) and not is_symlink:
                    data = await entry_resource.get_data()
                    entry_size = len(data)
                elif is_symlink and linkpath:
                    # For symlinks, the size is the length of the link target path
                    entry_size = len(linkpath)

                # Extract permission bits including setuid/setgid/sticky (not file type bits)
                permission_bits = entry_stat.st_mode & 0o7777

                # Build parameters dict - include linkpath for symlinks
                add_params = {
                    "entry_path": path,
                    "entry_size": entry_size,
                    "entry_data": data,
                    "filetype": filetype,
                    "permission": permission_bits,
                    "uid": entry_stat.st_uid,
                    "gid": entry_stat.st_gid,
                    "atime": entry_stat.st_atime,
                    "mtime": entry_stat.st_mtime,
                    "ctime": entry_stat.st_ctime,
                }
                if linkpath is not None:
                    add_params["linkpath"] = linkpath

                archive.add_file_from_memory(**add_params)

        # Combine all chunks into final bytes
        packed_bytes = b"".join(packed_chunks)
        resource.queue_patch(Range(0, await resource.get_data_length()), packed_bytes)


MagicMimePattern.register(CpioFilesystem, "application/x-cpio")
MagicDescriptionPattern.register(CpioFilesystem, lambda s: "cpio archive" in s)
