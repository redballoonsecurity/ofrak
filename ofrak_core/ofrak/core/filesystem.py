import os
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Type, Union

import xattr
from ofrak.resource import Resource

from ofrak.component.unpacker import UnpackerError
from ofrak.model.resource_model import index, ResourceAttributes
from ofrak.model.tag_model import ResourceTag
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceAttributeValueFilter,
    ResourceFilterCondition,
)


@dataclass
class FilesystemEntry(ResourceView):
    """
    Handles generic management of any entry stored within a filesystem.
    """

    name: str
    stat: Optional[os.stat_result]
    xattrs: Optional[Dict[str, bytes]]

    @index
    def Name(self) -> str:
        name = self.name.rstrip("/")
        return name.split("/")[-1]

    @classmethod
    def caption(cls, all_attributes) -> str:
        try:
            filesystem_attributes = all_attributes[FilesystemEntry.attributes_type]
        except KeyError:
            return super().caption(all_attributes)
        return f"{cls.__name__}: {filesystem_attributes.name}"

    def get_name(self) -> str:
        """
        Get the base name of a folder.

        :return: The file or folder's base name
        """
        return self.Name

    async def set_stat(self, stat_result: os.stat_result):
        """
        Set the stat for the `FilesystemEntry`. Useful for newly created files where we want to
        control the full 10-tuple.

        :param stat_result: `os.stat_result` object containing all necessary values
        """
        self.stat = stat_result
        if self.resource is None:
            return
        all_view_attrs: Dict[
            Type[ResourceAttributes], ResourceAttributes
        ] = self.get_attributes_instances()
        filesystem_attrs = all_view_attrs[FilesystemEntry.attributes_type]
        self.resource.add_attributes(filesystem_attrs)
        await self.resource.save()

    async def modify_stat_attribute(self, st_stat: int, stat_value: int):
        """
        Modify a specific `os.stat` attribute on the filesystem entry.

        Example:

        ```python
        fs_entry.modify_stat_attribute(stat.ST_MODE, 0o100755)
        ```

        :param st_stat: The `st_stat` struct member to be modified
        :param stat_value: The new stat value
        """
        if self.stat is None:
            raise ValueError("Cannot modify a stat attribute when stat attributes are not set")
        stat_attributes = list(self.stat)  # type: ignore
        stat_attributes[st_stat] = stat_value
        filesystem_stat_attributes = os.stat_result(tuple(stat_attributes))
        await self.set_stat(filesystem_stat_attributes)

    async def set_xattrs(self, xattrs: Dict[str, bytes]):
        """
        Set several extended file attributes ("xattrs") values.

        :param xattrs: Dictionary of xattr names (as strings) and values (as bytes) to set
        """
        self.xattrs = xattrs
        if self.resource is None:
            return
        all_view_attrs: Dict[
            Type[ResourceAttributes], ResourceAttributes
        ] = self.get_attributes_instances()
        filesystem_attrs = all_view_attrs[FilesystemEntry.attributes_type]
        self.resource.add_attributes(filesystem_attrs)
        await self.resource.save()

    async def modify_xattr_attribute(self, attribute: str, value: bytes):
        if self.xattrs is None:
            self.xattrs = dict()
        self.xattrs[attribute] = value
        if self.resource is None:
            return
        await self.resource.save()

    async def get_path(self) -> str:
        """
        Get a folder's path, with the `FilesystemRoot` as the path root.

        :return: The full path name, with the `FilesystemRoot` ancestor as the path root
        """
        path = [self.get_name()]

        for a in await self.resource.get_ancestors(
            r_filter=ResourceFilter(
                tags=(FilesystemEntry, FilesystemRoot),
                tags_condition=ResourceFilterCondition.OR,
            )
        ):
            if (a is None) or (a.has_tag(FilesystemRoot)):
                break
            a_view = await a.view_as(FilesystemEntry)
            path.append(a_view.get_name())
        path.reverse()

        return os.path.join(*path)

    def apply_stat_attrs(self, path: str):
        """
        Set file mode and access times of a path on disk to match the attributes stored on this
        resource.

        :param path: Path on disk to set attributes of.
        """
        if self.stat:
            os.chown(path, self.stat.st_uid, self.stat.st_gid)
            os.chmod(path, self.stat.st_mode)
            os.utime(path, (self.stat.st_atime, self.stat.st_mtime))
        if self.xattrs:
            for attr, value in self.xattrs.items():
                xattr.setxattr(path, attr, value)

    def is_file(self) -> bool:
        return self.resource.has_tag(File)

    def is_folder(self) -> bool:
        return self.resource.has_tag(Folder)

    def is_link(self) -> bool:
        return self.resource.has_tag(SymbolicLink)

    def is_block_device(self) -> bool:
        return self.resource.has_tag(BlockDevice)

    def is_fifo_pipe(self) -> bool:
        return self.resource.has_tag(FIFOPipe)

    def is_character_device(self) -> bool:
        return self.resource.has_tag(CharacterDevice)

    def is_device(self) -> bool:
        return self.is_block_device() or self.is_character_device()


class File(FilesystemEntry):
    """
    Stores the data and location of a file within a filesystem or folder's descendant file tree.
    """


class Folder(FilesystemEntry):
    """
    Describes a folder that is stored in a filesystem as a file tree.

    All descendant resources are stored in a tree structure that reflects a folder/directory's file
    tree.
    """

    async def get_entry(self, path: str) -> Optional[FilesystemEntry]:
        """
        Search a folder for an entry with the given path.

        :param path: The filesystem path to search for, relative to this folder

        :return: The child `FilesystemEntry` resource that was found. If nothing was found, `None`
        is returned
        """
        basename = os.path.basename(path)

        # only searching paths with the same base name should reduce the search space by quite a lot
        descendants = await self.resource.get_descendants_as_view(
            FilesystemEntry,
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(FilesystemEntry.Name, basename),)
            ),
        )

        for d in descendants:
            if d.get_path() == path and self.resource.get_tags() == d.resource.get_tags():
                return d
        return None

    async def list_dir(self) -> Dict[str, FilesystemEntry]:
        """
        Enumerate a folder's children, much like `os.listdir`.

        :return: A dictionary of child entries, with the child's name as the key
        """
        entries = dict()
        for c in await self.resource.get_children_as_view(FilesystemEntry):
            entries[c.get_name()] = c
        return entries


@dataclass
class SpecialFileType(FilesystemEntry):
    """
    A filesystem entry that is not a simple type, like a file or folder. For example, symbolic
    links and block devices fall under this category.
    """


@dataclass
class SymbolicLink(SpecialFileType):
    """
    Symbolic link pointing to a (possibly invalid) path in the filesystem. The path pointed to is
    invalid if accessing it would raise a `FileNotFoundError`.

    :ivar source_path: File pointed to by the symbolic link
    """

    source_path: str


@dataclass
class BlockDevice(SpecialFileType):
    """
    Block special device file.
    """


@dataclass
class FIFOPipe(SpecialFileType):
    """
    Named pipe.
    """


@dataclass
class CharacterDevice(SpecialFileType):
    """
    Character special device file.
    """


@dataclass
class FilesystemRoot(ResourceView):
    """
    A resource that contains a filesystem's file tree. All descendant resources are stored in a tree
    structure that reflects a filesystem's file tree. The methods within this class are intended to
    be used as utilities when unpacking any filesystem-like resource.

    Any resource that contains a file tree should inherit the `FilesystemRoot` class.
    """

    async def initialize_from_disk(
        self,
        path: str,
    ):
        root_path = os.path.normpath(path)
        for root, dirs, files in os.walk(root_path):
            for d in sorted(dirs):
                absolute_path = os.path.join(root, d)
                relative_path = os.path.join(os.path.relpath(root, root_path), d)
                folder_attributes_stat = os.lstat(absolute_path)

                mode = folder_attributes_stat.st_mode
                mode_tests = [
                    stat.S_ISCHR,
                    stat.S_ISBLK,
                    stat.S_ISFIFO,
                    stat.S_ISSOCK,
                    stat.S_ISDOOR,
                    stat.S_ISPORT,
                    stat.S_ISWHT,
                    stat.S_ISREG,
                ]
                for mode_test in mode_tests:
                    if mode_test(mode) != 0:
                        raise NotImplementedError(
                            f"Directory {absolute_path} has an unsupported special file type: "
                            f"{stat.S_IFMT(mode):o}. {mode_test.__name__} should be false."
                        )

                folder_attributes_xattr = self._get_xattr_map(absolute_path)
                if os.path.islink(absolute_path):
                    await self.add_special_file_entry(
                        relative_path,
                        SymbolicLink(
                            relative_path,
                            folder_attributes_stat,
                            folder_attributes_xattr,
                            os.readlink(absolute_path),
                        ),
                    )
                else:
                    await self.add_folder(
                        relative_path,
                        folder_attributes_stat,
                        folder_attributes_xattr,
                    )

            for f in sorted(files):
                absolute_path = os.path.join(root, f)
                relative_path = os.path.normpath(os.path.join(os.path.relpath(root, root_path), f))
                file_attributes_stat = os.lstat(absolute_path)

                mode = file_attributes_stat.st_mode
                mode_tests = [
                    stat.S_ISSOCK,
                    stat.S_ISDOOR,
                    stat.S_ISPORT,
                    stat.S_ISWHT,
                    stat.S_ISDIR,
                ]
                for mode_test in mode_tests:
                    if mode_test(mode) != 0:
                        raise NotImplementedError(
                            f"Directory {absolute_path} has an unsupported special file type: "
                            f"{stat.S_IFMT(mode):o}. {mode_test.__name__} should be false."
                        )

                file_attributes_xattr = self._get_xattr_map(absolute_path)
                if os.path.islink(absolute_path):
                    await self.add_special_file_entry(
                        relative_path,
                        SymbolicLink(
                            relative_path,
                            file_attributes_stat,
                            file_attributes_xattr,
                            os.readlink(absolute_path),
                        ),
                    )
                elif os.path.isfile(absolute_path):
                    with open(absolute_path, "rb") as fh:
                        await self.add_file(
                            relative_path,
                            fh.read(),
                            file_attributes_stat,
                            file_attributes_xattr,
                        )
                elif stat.S_ISFIFO(mode):
                    await self.add_special_file_entry(
                        relative_path,
                        FIFOPipe(relative_path, file_attributes_stat, file_attributes_xattr),
                    )
                elif stat.S_ISBLK(mode):
                    await self.add_special_file_entry(
                        relative_path,
                        BlockDevice(relative_path, file_attributes_stat, file_attributes_xattr),
                    )
                elif stat.S_ISCHR(mode):
                    await self.add_special_file_entry(
                        relative_path,
                        CharacterDevice(relative_path, file_attributes_stat, file_attributes_xattr),
                    )
                else:
                    raise NotImplementedError(
                        f"File {absolute_path} appeared to be a supported "
                        f"type but did not match any of the known cases to "
                        f"create a resource. Stat: {stat.S_IFMT(mode):o}"
                    )

    async def flush_to_disk(
        self,
        path: Optional[str] = None,
    ):
        """
        Writes this `FilesystemRoot`'s `FilesystemEntry` descendants to directory. If a target path
        is not provided, the output is written to a temporary directory.

        :return: the root directory containing the flushed filesystem
        """
        if path is None:
            root_path = tempfile.mkdtemp()
        else:
            root_path = path

        entries = [
            f
            for f in await self.resource.get_children_as_view(
                FilesystemEntry, r_filter=ResourceFilter(tags=(FilesystemEntry,))
            )
        ]
        while len(entries) > 0:
            entry = entries.pop(0)
            entry_path = await entry.get_path()
            if entry.is_link():
                link_name = os.path.join(root_path, entry_path)
                if not os.path.exists(link_name):
                    link_view = await entry.resource.view_as(SymbolicLink)
                    os.symlink(link_view.source_path, link_name)
                assert len(list(await entry.resource.get_children())) == 0
                if entry.stat:
                    # https://docs.python.org/3/library/os.html#os.supports_follow_symlinks
                    if os.chown in os.supports_follow_symlinks:
                        os.chown(
                            link_name, entry.stat.st_uid, entry.stat.st_gid, follow_symlinks=False
                        )
                    if os.chmod in os.supports_follow_symlinks:
                        os.chmod(link_name, entry.stat.st_mode, follow_symlinks=False)
                    if os.utime in os.supports_follow_symlinks:
                        os.utime(
                            link_name,
                            (entry.stat.st_atime, entry.stat.st_mtime),
                            follow_symlinks=False,
                        )
                if entry.xattrs:
                    for attr, value in entry.xattrs.items():
                        xattr.setxattr(link_name, attr, value, symlink=True)  # Don't follow links
            elif entry.is_folder():
                folder_name = os.path.join(root_path, entry_path)
                if not os.path.exists(folder_name):
                    os.makedirs(folder_name)
                for child in await entry.resource.get_children_as_view(
                    FilesystemEntry, r_filter=ResourceFilter(tags=(FilesystemEntry,))
                ):
                    entries.append(child)
            elif entry.is_file():
                file_name = os.path.join(root_path, entry_path)
                with open(file_name, "wb") as f:
                    f.write(await entry.resource.get_data())
                entry.apply_stat_attrs(file_name)
            elif entry.is_device():
                device_name = os.path.join(root_path, entry_path)
                if entry.stat is None:
                    raise ValueError(
                        f"Cannot create a device {entry_path} for a "
                        f"BlockDevice or CharacterDevice resource with no stat!"
                    )
                os.mknod(device_name, entry.stat.st_mode, entry.stat.st_rdev)
                entry.apply_stat_attrs(device_name)
            elif entry.is_fifo_pipe():
                fifo_name = os.path.join(root_path, entry_path)
                if entry.stat is None:
                    raise ValueError(
                        f"Cannot create a fifo {entry_path} for a FIFOPipe resource "
                        "with no stat!"
                    )
                os.mkfifo(fifo_name, entry.stat.st_mode)
                entry.apply_stat_attrs(fifo_name)
            else:
                entry_info = f"Stat: {stat.S_IFMT(entry.stat.st_mode):o}" if entry.stat else ""
                raise NotImplementedError(
                    f"FilesystemEntry {entry_path} has an unknown or "
                    f"unsupported filesystem type! Unable to create it "
                    f"on-disk. {entry_info}"
                )

        return root_path

    async def get_entry(self, path: str):
        """
        Searches this `FilesystemRoot`'s descendants for a filesystem entry with a given path,
            and returns that entry if found.

        :param path: the path of the `FilesystemEntry` to search for, with this `FilesystemRoot` as
        the path root

        :return: the descendant `FilesystemEntry`, if found; otherwise, returns `None`
        """
        basename = os.path.basename(path)

        # only searching paths with the same base name should reduce the search space by quite a lot
        descendants = await self.resource.get_descendants_as_view(
            FilesystemEntry,
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(FilesystemEntry.Name, basename),)
            ),
        )

        for d in descendants:
            if await d.get_path() == os.path.normpath(path):
                return d
        return None

    async def list_dir(self) -> dict:
        """
        Enumerates a `FilesystemRoot`'s children, much like `os.listdir`.

        :return: a dictionary of child entries, with the child's name as the key
        """
        entries = dict()
        for c in await self.resource.get_children_as_view(FilesystemEntry):
            entries[c.get_name()] = c
        return entries

    async def add_folder(
        self,
        path: str,
        folder_stat_result: Optional[os.stat_result] = None,
        folder_xattrs: Optional[Dict[str, bytes]] = None,
        tags: Iterable[ResourceTag] = (),
        attributes: Iterable[ResourceAttributes] = (),
    ) -> Folder:
        """
        Adds a [Folder][ofrak.core.filesystem.Folder] resource to a `FilesystemRoot`, creating all
        parent folders as needed.

        :param path: the path that will contain the folder to be added
        :param folder_stat_result: the filesystem attributes associated with the folder
        :param folder_xattrs: xattrs for the folder
        :param tags: the list of tags to be added to the new resource. The `Folder` tag is added by
        default
        :param attributes: the list of additional attributes to be added to the new folder, the
        folder's name attribute is added automatically

        :raises ValueError: if the path is too short and doesn't actually include any directories

        :return: the `Folder` resource that was added to the `FilesystemRoot`
        """
        # Normalizes and cleans up paths beginning with "./" and containing "./../" as well as
        # other extraneous separators
        split_dir = os.path.normpath(path).rstrip("/").lstrip("/").split("/")

        parent: Union[FilesystemRoot, Folder] = self
        for directory in split_dir:
            folder_entries = await parent.list_dir()

            if directory not in folder_entries.keys():
                new_missing_folder = await parent.resource.create_child_from_view(
                    Folder(directory, folder_stat_result, folder_xattrs),
                    data=b"",
                    additional_tags=tags,
                    additional_attributes=attributes,
                )
                parent = await new_missing_folder.view_as(Folder)
            else:
                parent = await folder_entries[directory].resource.view_as(Folder)

        if type(parent) is FilesystemRoot:
            assert len(split_dir) == 0  # Only case this should happen
            raise ValueError(f"The path {path} is too short (no directories)")

        if not isinstance(parent, Folder):
            raise ValueError(
                f"Parent folder {parent} has an unexpected type {type(parent)}. It "
                f"should be a Folder instead."
            )
        return parent

    async def add_file(
        self,
        path: str,
        data: bytes,
        file_stat_result: Optional[os.stat_result] = None,
        file_xattrs: Optional[Dict[str, bytes]] = None,
        tags: Iterable[ResourceTag] = (),
        attributes: Iterable[ResourceAttributes] = (),
    ) -> Resource:
        """
        Adds a [File][ofrak.core.filesystem.File] resource to a `FilesystemRoot`, creating all
        parent [Folders][ofrak.core.filesystem.Folder] as needed.

        :param path: the path that will contain the `File` to be added
        :param data: contents of the file being added
        :param file_stat_result: the filesystem attributes associated with the file
        :param file_xattrs: xattrs for the file
        :param tags: the list of tags to be added to the new resource, the File tag is added by
        default
        :param attributes: the list of additional attributes to be added to the new Folder,
            the file's name attribute is added automatically

        :return: the `File` resource that was added to the `FilesystemRoot`
        """
        dirname = os.path.dirname(path)
        filename = os.path.basename(path)

        if dirname == "":
            parent_folder = self
        else:
            parent_folder = await self.get_entry(dirname)
            if parent_folder is None:
                parent_folder = await self.add_folder(dirname)

        new_file = await parent_folder.resource.create_child_from_view(
            File(filename, file_stat_result, file_xattrs),
            data=data,
            additional_tags=tags,
            additional_attributes=attributes,
        )
        await parent_folder.resource.save()
        return new_file

    async def remove_file(self, path: str) -> None:
        """
        Removes a [File][ofrak.core.filesystem.File] resource from a `FilesystemRoot`.
        :param path: the path of the file to be removed
        :return: None
        """
        file_to_remove = await self.get_entry(path)
        await file_to_remove.resource.delete()
        await file_to_remove.resource.save()

    async def add_special_file_entry(
        self,
        path: str,
        special_file_view: SpecialFileType,
        tags: Iterable[ResourceTag] = (),
        attributes: Iterable[ResourceAttributes] = (),
    ) -> Resource:
        """
        Adds a resource representing a [SpecialFileType][ofrak.core.filesystem.SpecialFileType]
        to a `FilesystemRoot`, creating all parent [Folders][ofrak.core.filesystem.Folder] as
        needed.

        Some examples of these "special" types are
        [SymbolicLink][ofrak.core.filesystem.SymbolicLink] and
        [BlockDevice][ofrak.core.filesystem.BlockDevice].

        :param path: The path of the `FilesystemEntry` to be added
        :param special_file_view: A ResourceView, whose type should be a subclass of
        `FilesystemEntry`
        :param tags: the list of tags to be added to the new resource, the File tag is added by
        default
        :param attributes: the list of additional attributes to be added to the new Folder,
        the file's name attribute is added automatically

        :return: The special `FilesystemEntry` resource that was added to the `FilesystemRoot`
        """
        dirname = os.path.dirname(path)

        if dirname == "":
            parent_folder = self
        else:
            parent_folder = await self.get_entry(dirname)
            if parent_folder is None:
                parent_folder = await self.add_folder(dirname)

        new_entry = await parent_folder.resource.create_child_from_view(
            special_file_view,
            data=b"",  # Use empty, non-None data
            additional_tags=tags,
            additional_attributes=attributes,
        )
        return new_entry

    @classmethod
    def _get_xattr_map(cls, path):
        xattr_dict = {}
        for attr in xattr.listxattr(path, symlink=True):  # Don't follow links
            xattr_dict[attr] = xattr.getxattr(path, attr)
        return xattr_dict


async def unpack_with_command(command: List[str]):
    try:
        subprocess.run(command, check=True, capture_output=True)
    except subprocess.CalledProcessError as error:
        raise UnpackerError(format_called_process_error(error))


def format_called_process_error(error: subprocess.CalledProcessError) -> str:
    return (
        f"Command '{error.cmd}' returned non-zero exit status {error.returncode}. Stderr: "
        f"{error.stderr}. Stdout: {error.stdout}."
    )
