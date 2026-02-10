import asyncio
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError
from typing import Optional

from ofrak import Analyzer, Unpacker, Resource
from ofrak.component.packer import Packer, PackerError
from ofrak.core import (
    GenericBinary,
    FilesystemRoot,
    File,
    Folder,
    SpecialFileType,
    MagicDescriptionPattern,
)
from ofrak.model.component_model import ComponentExternalTool, ComponentConfig
from ofrak_type.range import Range

_DEBUGFS = ComponentExternalTool(
    "debugfs", "https://e2fsprogs.sourceforge.net/", "-V", brew_package="e2fsprogs"
)


@dataclass
class ExtFilesystem(GenericBinary, FilesystemRoot):
    block_size: Optional[int] = None
    block_count: Optional[int] = None
    blocks_per_group: Optional[int] = None
    inode_size: Optional[int] = None
    number_of_inodes: Optional[int] = None
    reserved_block_count: Optional[int] = None
    creator_os: Optional[str] = None
    filesystem_features: Optional[str] = None
    filesystem_revision: Optional[int] = None
    volume_label: Optional[str] = None
    last_mounted_directory: Optional[str] = None
    uuid: Optional[str] = None


@dataclass
class Ext2Filesystem(ExtFilesystem):
    """
    Linux EXT2 filesystem.
    """


@dataclass
class Ext3Filesystem(ExtFilesystem):
    """
    Linux EXT3 filesystem.
    """


@dataclass
class Ext4Filesystem(ExtFilesystem):
    """
    Linux EXT4 filesystem.
    """


class ExtAnalyzer(Analyzer[None, ExtFilesystem]):
    """
    Extracts EXT filesystem parameters from the superblock using dumpe2fs. These parameters are
    required for correctly repacking the filesystem with mke2fs.
    """

    targets = (ExtFilesystem,)
    outputs = (ExtFilesystem,)
    external_dependencies = (_DEBUGFS,)

    async def analyze(self, resource: Resource, config=None) -> ExtFilesystem:
        size = len(await resource.get_data())
        if size == 0:
            return ExtFilesystem()
        async with resource.temp_to_disk(suffix=".extfs") as temp_path:
            proc = await asyncio.create_subprocess_exec(
                "dumpe2fs",
                "-h",
                temp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode:
                raise CalledProcessError(
                    returncode=proc.returncode, cmd=["dumpe2fs", "-h", temp_path]
                )

            params = {}
            for line in stdout.decode().splitlines():
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                params[key.strip()] = value.strip()

            volume_label = params.get("Filesystem volume name")
            if volume_label == "<none>":
                volume_label = None

            last_mounted_directory = params.get("Last mounted on")
            if last_mounted_directory == "<not available>":
                last_mounted_directory = None

            revision_str = params.get("Filesystem revision #")
            filesystem_revision = None
            if revision_str:
                filesystem_revision = int(revision_str.split()[0])

            def _parse_optional_int(params: dict, key: str) -> Optional[int]:
                val = params.get(key)
                if val is not None:
                    return int(val)
                return None

            return ExtFilesystem(
                block_size=_parse_optional_int(params, "Block size"),
                block_count=_parse_optional_int(params, "Block count"),
                blocks_per_group=_parse_optional_int(params, "Blocks per group"),
                inode_size=_parse_optional_int(params, "Inode size"),
                number_of_inodes=_parse_optional_int(params, "Inode count"),
                reserved_block_count=_parse_optional_int(params, "Reserved block count"),
                creator_os=params.get("Filesystem OS type"),
                filesystem_features=params.get("Filesystem features"),
                filesystem_revision=filesystem_revision,
                volume_label=volume_label,
                last_mounted_directory=last_mounted_directory,
                uuid=params.get("Filesystem UUID"),
            )


class ExtUnpacker(Unpacker[None]):
    """
    Extracts files and directories from Linux Extended (EXT2/EXT3/EXT4) filesystems, the standard
    Linux filesystem family. These filesystems support full Unix permissions, symbolic links, hard
    links, and extended attributes. Use when analyzing disk images, partition dumps, or embedded
    system storage that uses EXT filesystems. Common in Linux-based embedded devices, development
    boards, and virtualized environments.
    """

    targets = (ExtFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (_DEBUGFS,)

    async def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        async with resource.temp_to_disk(suffix=".extfs") as temp_fs_path:
            with tempfile.TemporaryDirectory() as temp_dir:
                command = [
                    "debugfs",
                    "-R",
                    f"rdump / {temp_dir}",
                    temp_fs_path,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *command,
                )
                returncode = await proc.wait()
                if returncode:
                    raise CalledProcessError(returncode=returncode, cmd=command)

                fs_view = await resource.view_as(ExtFilesystem)
                await fs_view.initialize_from_disk(temp_dir)


class ExtPacker(Packer[None]):
    """
    Packs files and directories into a Linux Extended (EXT2/EXT3/EXT4) filesystem image using
    mke2fs. The filesystem type is determined by the resource's tag. The filesystem parameters
    (block size, block count, etc.) are preserved from the original image via ExtAnalyzer.
    """

    targets = (ExtFilesystem,)
    external_dependencies = (_DEBUGFS,)

    async def pack(self, resource: Resource, config: ComponentConfig = None) -> None:
        ext_view = await resource.view_as(ExtFilesystem)
        flush_dir = await ext_view.flush_to_disk()
        original_size = await resource.get_data_length()

        if resource.has_tag(Ext2Filesystem):
            ext_type = "ext2"
        elif resource.has_tag(Ext3Filesystem):
            ext_type = "ext3"
        elif resource.has_tag(Ext4Filesystem):
            ext_type = "ext4"
        else:
            raise PackerError(
                f"Cannot pack {resource} because it is not one of [Ext2Filesystem, Ext3Filesystem, Ext4Filesystem]."
            )
        if not ext_view.block_size or not ext_view.block_count:
            raise PackerError(f"Cannot pack {resource}. block_size and block_count are required.")

        with tempfile.NamedTemporaryFile(mode="rb", suffix=".img", delete_on_close=False) as temp:
            temp.close()
            cmd = [
                "mke2fs",
                "-t",
                ext_type,
                "-b",
                str(ext_view.block_size),
                "-d",
                flush_dir,
            ]

            if ext_view.blocks_per_group:
                cmd.extend(["-g", str(ext_view.blocks_per_group)])
            if ext_view.inode_size:
                cmd.extend(["-I", str(ext_view.inode_size)])
            if ext_view.number_of_inodes:
                cmd.extend(["-N", str(ext_view.number_of_inodes)])
            if ext_view.reserved_block_count and ext_view.block_count > 0:
                percentage = round(ext_view.reserved_block_count / ext_view.block_count * 100)
                cmd.extend(["-m", str(percentage)])
            if ext_view.creator_os:
                cmd.extend(["-o", ext_view.creator_os])
            if ext_view.filesystem_features:
                features = "none," + ext_view.filesystem_features.replace(" ", ",")
                cmd.extend(["-O", features])
            if ext_view.filesystem_revision:
                cmd.extend(["-r", str(ext_view.filesystem_revision)])
            if ext_view.volume_label:
                cmd.extend(["-L", ext_view.volume_label])
            if ext_view.last_mounted_directory:
                cmd.extend(["-M", ext_view.last_mounted_directory])
            if ext_view.uuid:
                cmd.extend(["-U", ext_view.uuid])

            cmd.extend([temp.name, str(ext_view.block_count)])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            returncode = await proc.wait()
            if returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)

            with open(temp.name, "rb") as new_fh:
                new_data = new_fh.read()

            resource.queue_patch(Range(0, original_size), new_data)


MagicDescriptionPattern.register(Ext2Filesystem, lambda s: "ext2 filesystem" in s.lower())
MagicDescriptionPattern.register(Ext3Filesystem, lambda s: "ext3 filesystem" in s.lower())
MagicDescriptionPattern.register(Ext4Filesystem, lambda s: "ext4 filesystem" in s.lower())
