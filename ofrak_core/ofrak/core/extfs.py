import asyncio
import math
import os
import posixpath
import tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError
from typing import (
    Dict,
    Optional,
    Sequence,
    TextIO,
    Union,
    TypeVar,
    List,
    AsyncIterator,
    MutableSequence,
    Deque,
    Tuple,
)
from uuid import UUID
from collections import deque

from ofrak import Resource, ResourceAttributes
from ofrak.component.analyzer import Analyzer
from ofrak.component.packer import Packer
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import (
    FilesystemEntry,
    SymbolicLink,
    Folder,
    FilesystemRoot,
    File,
    Folder,
    SpecialFileType,
)
from ofrak.core.magic import MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentExternalTool, ComponentConfig
from ofrak_type.range import Range


_DEBUGFS = ComponentExternalTool(
    "debugfs", "https://e2fsprogs.sourceforge.net/", "-V", brew_package="e2fsprogs"
)

_MKE2FS = ComponentExternalTool(
    "mke2fs", "https://e2fsprogs.sourceforge.net/", "-V", brew_package="e2fsprogs"
)

_TUNE2FS = ComponentExternalTool(
    "tune2fs", "https://e2fsprogs.sourceforge.net/", "-V", brew_package="e2fsprogs"
)


@dataclass
class ExtFilesystem(GenericBinary, FilesystemRoot):
    pass


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


class ExtUnpacker(Unpacker[None]):
    """
    Unpack a Linux EXT filesystem.
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


RV = TypeVar("RV", Folder, FilesystemRoot)


async def walk_filesystem(
    root: RV, root_path: str
) -> AsyncIterator[
    Tuple[str, Union[RV, Folder], MutableSequence[Folder], Sequence[FilesystemEntry]]
]:
    entries: Deque[Tuple[str, Union[RV, Folder]]] = deque([(root_path, root)])

    while len(entries) > 0:
        path, view = entries.popleft()
        children = list(await view.resource.get_children_as_view(FilesystemEntry))
        folders: List[Folder] = []
        files: List[FilesystemEntry] = []
        for child in children:
            if child.is_folder():
                folders.append(await child.resource.view_as(Folder))
            else:
                files.append(child)
        yield path, view, folders, files
        entries.extend((posixpath.join(path, folder.Name), folder) for folder in folders)


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ExtFilesystemAttributes(ResourceAttributes):
    label: Optional[str]
    uuid: UUID
    features: Sequence[str]
    inode_count: int
    inode_size: int
    block_count: int
    block_size: int
    reserved_block_count: int
    fragment_size: int


class ExtAnalyzer(Analyzer[None, ExtFilesystemAttributes]):
    """
    Unpack a Linux EXT filesystem.
    """

    targets = (ExtFilesystem,)
    outputs = (ExtFilesystemAttributes,)
    external_dependencies = (_TUNE2FS,)

    @staticmethod
    async def _analyze_path(path: str) -> ExtFilesystemAttributes:
        command = ["tune2fs", "-l", path]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=command, stderr=stderr)

        fields: Dict[str, str] = {}
        for line in stdout.splitlines():
            field, _, value = line.decode().partition(":")
            if not value:
                continue
            fields[field] = value.strip()

        label: Optional[str] = fields["Filesystem volume name"]
        if label == "<none>":
            label = None

        return ExtFilesystemAttributes(
            label=label,
            uuid=UUID(fields["Filesystem UUID"]),
            features=fields["Filesystem features"].split(),
            inode_count=int(fields["Inode count"]),
            inode_size=int(fields["Inode size"]),
            block_count=int(fields["Block count"]),
            block_size=int(fields["Block size"]),
            fragment_size=int(fields["Fragment size"]),
            reserved_block_count=int(fields["Reserved block count"]),
        )

    async def analyze(
        self, resource: Resource, config: ComponentConfig = None
    ) -> ExtFilesystemAttributes:
        with tempfile.NamedTemporaryFile(suffix=".extfs") as temp_fs_file:
            temp_fs_file.write(await resource.get_data())
            temp_fs_file.flush()

            return await self._analyze_path(temp_fs_file.name)


@dataclass
class _DebugfsScriptWriter:
    buffer: TextIO

    def writecmd(self, data: str):
        print(data, file=self.buffer)

    async def write_file(self, path: str, entry: FilesystemEntry, data_dir: str):
        with tempfile.NamedTemporaryFile("wb", dir=data_dir, delete=False) as f:
            f.write(await entry.resource.get_data())

        self.writecmd(f'write "{f.name}" "{path}"')

    def mkdir(self, path: str):
        self.writecmd(f'mkdir "{path}"')

    def mknod(self, path: str, entry: FilesystemEntry):
        if entry.is_fifo_pipe():
            return f'mknod "{path}" p\n'
        elif entry.is_character_device():
            t = "c"
        elif entry.is_block_device():
            t = "d"

        rdev = entry.stat.st_rdev
        self.writecmd(f'mknod "{path}" {t} {os.major(rdev)} {os.minor(rdev)}\n')

    def symlink(self, path: str, symlink: SymbolicLink):
        self.writecmd(f'symlink "{path}" "{symlink.source_path}"')

    @staticmethod
    def _st_xtime_to_ext(st_xtime: Union[int, float], st_xtime_ns: int, extra_time: bool):
        st_xtime = int(st_xtime)
        if not extra_time:
            if st_xtime < -0x80000000 or st_xtime >= 0x80000000:
                st_xtime = 0
            return st_xtime, None

        if st_xtime < -0x80000000 or st_xtime >= 0x380000000:  # ext 4 range
            return 0, 0

        if st_xtime_ns is None:
            st_xtime_ns = 0

        epoch = ((st_xtime + 0x80000000) >> 32) & 0x3
        return st_xtime - (epoch << 32), (st_xtime_ns << 2) | epoch

    def set_stat(self, path: str, entry: FilesystemEntry, extra_time: bool):
        stat = entry.stat
        if stat is None:
            return

        fields = [
            ("mode", f"0{stat.st_mode:o}"),
            ("uid", stat.st_uid),
            ("gid", stat.st_gid),
        ]

        for xtime in "atime", "mtime", "ctime":
            st_xtime = int(getattr(stat, f"st_{xtime}"))
            st_xtime_ns = getattr(stat, f"st_{xtime}_ns", None)
            if st_xtime_ns is not None:
                st_xtime_ns = int(st_xtime_ns) % 1000000000
            ext_xtime, ext_xtime_extra = self._st_xtime_to_ext(st_xtime, st_xtime_ns, extra_time)
            fields.append((f"{xtime}_lo", ext_xtime))
            if ext_xtime_extra is not None:
                fields.append((f"{xtime}_extra", ext_xtime_extra))

        for field, val in fields:
            self.writecmd(f'set_inode_field "{path}" {field} {val}')


class ExtPacker(Packer[None]):
    """
    Pack a Linux EXT filesystem.
    """

    targets = (ExtFilesystem,)
    external_dependencies = (_MKE2FS, _DEBUGFS)

    @classmethod
    async def mke2fs(cls, resource: Resource, path: str):
        if resource.has_tag(Ext2Filesystem):
            type_str = "ext2"
        elif resource.has_tag(Ext3Filesystem):
            type_str = "ext3"
        elif resource.has_tag(Ext4Filesystem):
            type_str = "ext4"
        else:
            raise ValueError(
                "Resource must have Ext2Filesystem, Ext3Filesystem, or Ext4Filesystem tag"
            )

        ext_fs_attrs = await resource.analyze(ExtFilesystemAttributes)

        mke2fs_cmd = [
            "mke2fs",
            "-t",
            type_str,
            "-U",
            str(ext_fs_attrs.uuid),
            "-O",
            ",".join(ext_fs_attrs.features),
            "-N",
            str(ext_fs_attrs.inode_count),
            "-I",
            str(ext_fs_attrs.inode_size),
            "-b",
            str(ext_fs_attrs.block_size),
        ]

        if ext_fs_attrs.label is not None:
            mke2fs_cmd.extend(["-L", ext_fs_attrs.label])

        # check if we can set the reserved block count with mke2fs or we need to call
        # tune2fs later to get the precise number (unlikely unless it was manually set
        # on the input image)
        reserved_blocks_pct = math.ceil(
            ext_fs_attrs.reserved_block_count / ext_fs_attrs.block_count * 100
        )
        if (
            reserved_blocks_pct * ext_fs_attrs.block_count // 100
            == ext_fs_attrs.reserved_block_count
        ):
            mke2fs_cmd.extend(["-m", str(reserved_blocks_pct)])
            need_tune2fs_reserved_block = False
        else:
            need_tune2fs_reserved_block = True

        mke2fs_cmd.extend([path, str(ext_fs_attrs.block_count)])

        proc = await asyncio.create_subprocess_exec(
            *mke2fs_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode:
            raise CalledProcessError(
                returncode=proc.returncode, cmd=mke2fs_cmd, output=stdout, stderr=stderr
            )

        if need_tune2fs_reserved_block:
            tune2fs_cmd = [
                "tune2fs",
                "-r",
                str(ext_fs_attrs.reserved_block_count),
                path,
            ]
            proc = await asyncio.create_subprocess_exec(
                *tune2fs_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode:
                raise CalledProcessError(
                    returncode=proc.returncode,
                    cmd=tune2fs_cmd,
                    output=stdout,
                    stderr=stderr,
                )

    @classmethod
    async def _flush_to_disk_and_generate_debugfs_script(
        cls, root: ExtFilesystem, data_dir: str, script: _DebugfsScriptWriter
    ):
        ext_fs_attrs = await root.resource.analyze(ExtFilesystemAttributes)
        extra_time = root.resource.has_tag(Ext4Filesystem) and ext_fs_attrs.inode_size > 128

        async for parent, _, folders, files in walk_filesystem(root, ""):
            script.writecmd(f'cd "/{parent}"')

            for folder in folders:
                script.mkdir(folder.Name)
                script.set_stat(folder.Name, folder, extra_time)

            for file in files:
                if file.is_file():
                    await script.write_file(file.Name, file, data_dir)
                elif file.is_link():
                    script.symlink(file.Name, await file.resource.view_as(SymbolicLink))
                elif file.is_fifo_pipe() or file.is_character_device() or file.is_block_device():
                    script.mknod(file.Name, file)
                else:
                    raise RuntimeError(
                        "Bug! FilesystemEntry was not a file, symlink or special file"
                    )

                script.set_stat(file.Name, file, extra_time)

    async def pack(self, resource: Resource, config: ComponentConfig = None) -> None:
        filesystem = await resource.view_as(ExtFilesystem)

        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = os.path.join(temp_dir, "data")
            os.mkdir(data_dir)
            script = os.path.join(temp_dir, "debugfs_script")
            outfile = os.path.join(temp_dir, "out.extfs")

            await self.mke2fs(resource, outfile)

            with open(script, "w") as script_file:
                await self._flush_to_disk_and_generate_debugfs_script(
                    filesystem, data_dir, _DebugfsScriptWriter(script_file)
                )

            debugfs_cmd = [
                "debugfs",
                "-w",
                "-f",
                script,
                outfile,
            ]

            proc = await asyncio.create_subprocess_exec(
                *debugfs_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode:
                raise CalledProcessError(
                    returncode=proc.returncode,
                    cmd=debugfs_cmd,
                    output=stdout,
                    stderr=stderr,
                )

            with open(outfile, "rb") as f:
                new_fs_data = f.read()

            orig_fs_size = await resource.get_data_length()
            resource.queue_patch(Range(0, min(len(new_fs_data), orig_fs_size)), new_fs_data)

            if orig_fs_size > len(new_fs_data):
                resource.queue_patch(
                    Range(len(new_fs_data), orig_fs_size),
                    b"\0" * (orig_fs_size - len(new_fs_data)),
                )


MagicDescriptionIdentifier.register(Ext2Filesystem, lambda s: "ext2 filesystem" in s.lower())
MagicDescriptionIdentifier.register(Ext3Filesystem, lambda s: "ext3 filesystem" in s.lower())
MagicDescriptionIdentifier.register(Ext4Filesystem, lambda s: "ext4 filesystem" in s.lower())
