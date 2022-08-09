import os
import stat
import tempfile
from abc import ABC, abstractmethod

import xattr

from ofrak import OFRAKContext
from ofrak.resource import Resource


class FilesystemPackUnpackVerifyPattern(ABC):
    """
    Generic test pattern for filesystem packer/unpackers to ensure that no information is lost
    after packing and unpacking a filesystem of more than one file.
    """

    def setup(self):
        """
        Override to set values before the test is run. For example use this to change the value of
        self.check_xattrs in a subclass.
        """
        self.check_xattrs = True
        self.check_stat = True

    async def test_pack_unpack_verify(self, ofrak_context: OFRAKContext):
        self.setup()
        with tempfile.TemporaryDirectory() as root_path:
            self.create_local_file_structure(root_path)
            root_resource = await self.create_root_resource(ofrak_context, root_path)
            await self.unpack(root_resource)
            await self.repack(root_resource)
            with tempfile.TemporaryDirectory() as extract_dir:
                await self.extract(root_resource, extract_dir)
                self.verify_filesystem_equality(root_path, extract_dir)

    def _dirs_from_list(self, parent, names, depth):
        # Create a file
        if depth == 0:
            for filename in names:
                with open(os.path.join(parent, f"{filename}.txt"), "w") as f:
                    f.write(filename)
            return

        # Create another layer of directories
        for d in names:
            path = os.path.join(parent, d)
            os.mkdir(path)
            self._dirs_from_list(path, names, depth - 1)

    def create_local_file_structure(self, root: str):
        """
        Create a local file structure with multiple folders and files, many with different
        permissions and xattrs. Return the path to the root directory. Override this method to
        test with a different directory structure, or to add xattrs or stat values.
        """
        self._dirs_from_list(root, ["a", "b", "c", "d"], 3)

    @abstractmethod
    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        """
        Create a packed version of the filesystem outside of OFRAK that it can test unpacking and
        repacking.
        """
        raise NotImplementedError()

    @abstractmethod
    async def unpack(self, root_resource: Resource):
        """
        Unpack the filesystem using the OFRAK unpackers that are being tested.
        """
        raise NotImplementedError()

    @abstractmethod
    async def repack(self, root_resource: Resource):
        """
        Repack the filesystem using the OFRAK packers that are being tested.
        """
        raise NotImplementedError()

    @abstractmethod
    async def extract(self, root_resource: Resource, extract_dir: str):
        """
        Flush the packed filesystem to disk and then extract it using a method outside of OFRAK
        so the resulting path can be compared with the original.
        """
        raise NotImplementedError()

    def verify_filesystem_equality(self, old_path: str, new_path: str):
        if self.check_stat:
            self._validate_stat_equality(old_path, new_path)
        if self.check_xattrs:
            self._validate_xattrs_equality(old_path, new_path)
        self._validate_type_equality(old_path, new_path)
        if os.path.islink(old_path):
            self._validate_link_equality(old_path, new_path)
        elif os.path.isfile(old_path):
            self._validate_file_data_equality(old_path, new_path)
        elif os.path.isdir(old_path):
            self._validate_folder_equality(old_path, new_path)
        else:
            self._validate_special_file_equality(old_path, new_path)

    def _validate_stat_equality(self, old_path: str, new_path: str):
        old_stat = os.lstat(old_path)
        new_stat = os.lstat(new_path)
        assert (
            old_stat == new_stat
        ), f"{old_path} and {new_path} have different stat values\nold: {old_stat}\nnew: {new_stat}"

    def _validate_xattrs_equality(self, old_path: str, new_path: str):
        old_xattrs = dict()
        for attr in xattr.listxattr(old_path, symlink=True):
            old_xattrs[attr] = xattr.getxattr(old_path, attr, symlink=True)
        new_xattrs = dict()
        for attr in xattr.listxattr(new_path, symlink=True):
            new_xattrs[attr] = xattr.getxattr(new_path, attr, symlink=True)
        assert (
            old_xattrs == new_xattrs
        ), f"{old_path} and {new_path} have different xattrs\nold: {old_xattrs}\nnew: {new_xattrs}"

    def _validate_type_equality(self, old_path: str, new_path: str):
        assert (
            os.path.isdir(old_path) == os.path.isdir(new_path)
            and os.path.isfile(old_path) == os.path.isfile(new_path)
            and os.path.islink(old_path) == os.path.islink(new_path)
            and os.path.ismount(old_path) == os.path.ismount(new_path)
        ), f"{old_path} and {new_path} are not the same type (file/folder/symlink)"

    def _validate_file_data_equality(self, old_path: str, new_path: str):
        with open(old_path, "rb") as old_f, open(new_path, "rb") as new_f:
            assert (
                old_f.read() == new_f.read()
            ), f"{old_path} and {new_path} do not contain the same data"

    def _validate_folder_equality(self, old_path: str, new_path: str):
        old_files = os.listdir(old_path)
        new_files = os.listdir(new_path)
        assert len(old_files) == len(new_files) and set(old_files) == set(
            new_files
        ), f"{old_path} and {new_path} contain different files\nold: {old_files}\nnew: {new_files}"

        for old_f, new_f in zip(old_files, new_files):
            old_f = os.path.join(old_path, old_f)
            new_f = os.path.join(new_path, new_f)
            self.verify_filesystem_equality(old_f, new_f)

    def _validate_link_equality(self, old_path: str, new_path: str):
        old_source = os.readlink(old_path)
        new_source = os.readlink(new_path)
        assert old_source == new_source, (
            f"{old_path} and {new_path} point to different files\n"
            f"old: {old_source}\nnew: {new_source}"
        )

    def _validate_special_file_equality(self, old_path: str, new_path: str):
        old_stat = os.lstat(old_path)
        new_stat = os.lstat(new_path)
        assert old_stat.st_mode == new_stat.st_mode, (
            f"{old_path} and {new_path} have different "
            f"modes ({stat.S_IFMT(old_stat.st_mode):o} vs {stat.S_IFMT(new_stat.st_mode):o})"
        )
        assert old_stat.st_uid == new_stat.st_uid, (
            f"{old_path} and {new_path} have different "
            f"uids ({old_stat.st_uid} vs {new_stat.st_uid})"
        )
        assert old_stat.st_gid == new_stat.st_gid, (
            f"{old_path} and {new_path} have different "
            f"gids ({old_stat.st_gid} vs {new_stat.st_gid})"
        )
