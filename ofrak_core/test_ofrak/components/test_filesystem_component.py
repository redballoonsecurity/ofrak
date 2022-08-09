import os
import subprocess
import tempfile
from abc import ABC
from typing import Type, List

import pytest

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import format_called_process_error, FilesystemEntry, FilesystemRoot
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource, RV
from ofrak_components.cpio import CpioFilesystem, CpioArchiveType
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from ofrak_components.tar import TarArchive
from ofrak_components.zip import ZipArchive
from pytest_ofrak.patterns.pack_unpack_filesystem import FilesystemPackUnpackVerifyPattern
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

CHILD_TEXTFILE_NAME = "hello.txt"
CHILD_FOLDER = "test_folder"
SUBCHILD_TEXTFILE_NAME = "goodbye.txt"
SUBCHILD_FOLDER = "test_subfolder"

CHILD_TEXT = "Hello World\n"
SUBCHILD_TEXT = "Goodbye World\n"
NUM_TREE_ITEMS = 4
NUM_FILES = 2
NUM_FOLDERS = 2

EXPECTED_CHILD_TEXT = "Hello OFrak\n"
EXPECTED_SUBCHILD_TEXT = "Goodbye OFrak\n"

ZIPFILE_NAME = "test.zip"

TAGS = [
    (ZipArchive, []),
    (TarArchive, []),
    (CpioFilesystem, [CpioFilesystem.attributes_type(CpioArchiveType.BINARY)]),
]


@pytest.mark.parametrize("tag, attr", TAGS)
class FilesystemPattern(UnpackModifyPackPattern, ABC):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as temp_dir:
            child_folder = os.path.join(temp_dir, CHILD_FOLDER)
            child_file = os.path.join(temp_dir, CHILD_TEXTFILE_NAME)
            subchild_file = os.path.join(child_folder, SUBCHILD_TEXTFILE_NAME)
            subchild_folder = os.path.join(child_folder, SUBCHILD_FOLDER)

            if not os.path.exists(child_folder):
                os.mkdir(child_folder)
            if not os.path.exists(subchild_folder):
                os.mkdir(subchild_folder)

            with open(child_file, "w") as f:
                f.write(CHILD_TEXT)
            with open(subchild_file, "w") as f:
                f.write(SUBCHILD_TEXT)

            resource = await ofrak_context.create_root_resource(
                name=temp_dir, data=b"", tags=[FilesystemRoot]
            )
            await resource.save()
            filesystem_view = await resource.view_as(FilesystemRoot)
            await filesystem_view.initialize_from_disk(temp_dir)
            resource.add_tag(self.tag)
            for attr in self.attr:
                resource.add_attributes(attr)
            await resource.save()
            await resource.pack_recursively()

            return resource

    async def unpack(self, resource: Resource) -> None:
        await resource.unpack()

    async def repack(self, resource: Resource) -> None:
        await resource.pack_recursively()

    @pytest.fixture(autouse=True)
    def add_tag(self, tag: Type[RV], attr: List[ResourceAttributes]):
        self.tag = tag
        self.attr = attr


class TestFilesystemAddFile(FilesystemPattern):
    #  TODO: add file attrs and check
    async def modify(self, unpacked_resource: Resource) -> None:
        print(await unpacked_resource.summarize_tree())
        unpacked_resource_view = await unpacked_resource.view_as(self.tag)
        await unpacked_resource_view.add_file("test_folder/test.txt", b"test")
        print(await unpacked_resource.summarize_tree())

    async def verify(self, repacked_zip_resource: Resource) -> None:
        await repacked_zip_resource.unpack()
        print(await repacked_zip_resource.summarize_tree())
        repacked_zip_resource_view = await repacked_zip_resource.view_as(self.tag)
        new_file = await repacked_zip_resource_view.get_entry("test_folder/test.txt")
        assert new_file is not None
        assert await new_file.resource.get_data() == b"test"


class TestFilesystemRemoveFile(FilesystemPattern):
    async def modify(self, unpacked_resource: Resource) -> None:
        unpacked_resource_view = await unpacked_resource.view_as(self.tag)
        await unpacked_resource_view.remove_file("test_folder/goodbye.txt")

    async def verify(self, repacked_resource: Resource) -> None:
        await repacked_resource.unpack()
        repacked_resource_view = await repacked_resource.view_as(self.tag)
        old_file = await repacked_resource_view.get_entry("test_folder/goodbye.txt")
        assert old_file is None


class TestFilesystemComponent(FilesystemPattern):
    async def modify(self, resource: Resource) -> None:
        zip_archive = await resource.view_as(self.tag)
        child_text_string_config = StringPatchingConfig(6, "OFrak")
        child_textfile = await zip_archive.get_entry("hello.txt")
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

        subchild_text_string_config = StringPatchingConfig(8, "OFrak")
        subchild_textfile = await zip_archive.get_entry("test_folder/goodbye.txt")
        await subchild_textfile.resource.run(StringPatchingModifier, subchild_text_string_config)

    async def verify(self, resource: Resource) -> None:
        await resource.unpack()
        resource_view = await resource.view_as(self.tag)
        flush_tmp = await resource_view.flush_to_disk()

        dirs = []
        files_dict = {}
        for root, directories, files in os.walk(flush_tmp):
            for d in directories:
                dirs.append(d)
            for f in files:
                with open(os.path.join(root, f)) as fh:
                    files_dict[f] = fh.read()
        assert len(dirs) == NUM_FOLDERS
        assert len(files_dict.keys()) == NUM_FILES

        assert set(dirs) == {"test_folder", "test_subfolder"}
        assert sorted(list(files_dict.keys())) == sorted(["goodbye.txt", "hello.txt"])

        assert files_dict["hello.txt"] == EXPECTED_CHILD_TEXT
        assert files_dict["goodbye.txt"] == EXPECTED_SUBCHILD_TEXT


class TestSymbolicLinkUnpackPack(FilesystemPackUnpackVerifyPattern):
    def setup(self):
        super().setup()
        self.check_stat = False

    def create_local_file_structure(self, root: str):
        """
        Create filesystem tree:
        ```
        /tmp/tst
        ├── bar.txt -> /tmp/tst/foo.txt
        ├── fake.txt -> /tmp/tst/nonexistent.txt
        ├── foo.txt -> /tmp/tst/rick.txt
        ├── infinite_dir
        │   ├── recurse -> /tmp/tst/infinite_dir
        │   └── test.txt
        ├── link_1.txt -> /tmp/tst/link_3.txt
        ├── link_2.txt -> /tmp/tst/link_1.txt
        ├── link_3.txt -> /tmp/tst/link_2.txt
        ├── outer.txt -> /tmp/tst/test_dir/astley.txt
        ├── rick.txt
        ├── test_alias -> /tmp/tst/test_dir
        └── test_dir
            ├── astley.txt
            ├── relative.txt -> ../outer.txt
            └── inner.txt -> /tmp/tst/test_dir/astley.txt
        ```
        """
        self.create_symlinked_file(root)
        self.create_symlinked_directory(root)
        self.create_symlink_file_cycle(root)
        self.create_symlink_directory_cycle(root)
        self.create_broken_symlink(root)

    def create_symlinked_file(self, root: str):
        """
        Create a text file, a symbolic link to that file, and a symbolic link to the symbolic link.
        """
        test_path = os.path.join(root, "rick.txt")
        with open(test_path, "w") as f:
            f.write(
                "We're no strangers to love\n"
                "You know the rules and so do I\n"
                "A full commitment's what I'm thinking of\n"
                "You wouldn't get this from any other guy"
            )

        foo_path = os.path.join(root, "foo.txt")
        bar_path = os.path.join(root, "bar.txt")
        os.symlink(test_path, foo_path)
        os.symlink(foo_path, bar_path)

    def create_symlinked_directory(self, root: str):
        """
        Create a directory, a symbolic link to the directory, a file in the directory, and symbolic
        links to the file both inside and outside the directory. Also create a relative symlink
        inside the directory pointing to the symlink outside the directory.
        """
        dir_path = os.path.join(root, "test_dir")
        os.mkdir(dir_path)

        test_path = os.path.join(dir_path, "astley.txt")
        with open(test_path, "w") as f:
            f.write(
                "Never gonna give you up\n"
                "Never gonna let you down\n"
                "Never gonna run around and desert you\n"
                "Never gonna make you cry\n"
                "Never gonna say goodbye\n"
                "Never gonna tell a lie and hurt you"
            )

        dir_alias_path = os.path.join(root, "test_alias")
        os.symlink(dir_path, dir_alias_path)
        inner_link_path = os.path.join(dir_path, "inner.txt")
        os.symlink(test_path, inner_link_path)
        outer_link_path = os.path.join(root, "outer.txt")
        os.symlink(test_path, outer_link_path)

        relative_link_path = os.path.join(dir_path, "relative.txt")
        os.symlink("../outer.txt", relative_link_path)

    def create_symlink_file_cycle(self, root: str, num_links: int = 3):
        """
        Create a cycle of symbolic links like: `1 <- 2 <- 3 <- 1`.
        """
        links = [os.path.join(root, f"link_{i + 1}.txt") for i in range(num_links)]
        for i in range(len(links)):
            os.symlink(links[i], links[(i + 1) % len(links)])

    def create_symlink_directory_cycle(self, root: str):
        """
        Create a directory, and a symbolic link inside the directory pointing to the directory
        itself.
        """
        dir_path = os.path.join(root, "infinite_dir")
        os.mkdir(dir_path)

        dir_file_path = os.path.join(dir_path, "test.txt")
        with open(dir_file_path, "w") as f:
            f.write("Testing")

        dir_alias_path = os.path.join(dir_path, "recurse")
        os.symlink(dir_path, dir_alias_path)

    def create_broken_symlink(self, root: str):
        """
        Create a link to a file or folder that does not actually exist on the filesystem.
        """
        fake_source_path = os.path.join(root, "nonexistent.txt")
        fake_dest_path = os.path.join(root, "fake.txt")
        os.symlink(fake_source_path, fake_dest_path)

    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        # Pack with command line `tar` because it supports symbolic links
        with tempfile.NamedTemporaryFile(suffix=".tar") as archive:
            command = ["tar", "--xattrs", "-C", directory, "-cf", archive.name, "."]
            try:
                subprocess.run(command, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(format_called_process_error(e))

            return await ofrak_context.create_root_resource_from_file(archive.name)

    async def unpack(self, root_resource: Resource):
        await root_resource.unpack_recursively()

    async def repack(self, root_resource: Resource):
        await root_resource.pack_recursively()

    async def extract(self, root_resource: Resource, extract_dir: str):
        with tempfile.NamedTemporaryFile(suffix=".tar") as tar:
            data = await root_resource.get_data()
            tar.write(data)
            tar.flush()

            command = ["tar", "--xattrs", "-C", extract_dir, "-xf", tar.name]
            try:
                subprocess.run(command, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(format_called_process_error(e))


class TestLoadInMemoryFilesystem(TestSymbolicLinkUnpackPack):
    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        with tempfile.TemporaryDirectory() as archive_dir:
            archive_name = os.path.join(archive_dir, "archive.tar")
            command = ["tar", "--xattrs", "-C", directory, "-cf", archive_name, "."]
            try:
                subprocess.run(command, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(format_called_process_error(e))

            with open(archive_name, "rb") as f:
                data = f.read()

            root_resource = await ofrak_context.create_root_resource(
                "Non-TAR parent",
                b"",
                tags=(FilesystemEntry,),
            )
            child = await root_resource.create_child(data=b"", tags=(GenericBinary,))
            await child.create_child(data=data, tags=(GenericBinary,))
            return root_resource

    async def extract(self, root_resource: Resource, extract_dir: str):
        child = await root_resource.get_only_child()
        child = await child.get_only_child()
        await super().extract(child, extract_dir)
