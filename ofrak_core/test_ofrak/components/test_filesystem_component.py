import os
import re
import stat
import subprocess
from ofrak import tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.core import FilesystemRoot
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import (
    FilesystemEntry,
    Folder,
)
from ofrak.resource import Resource
from pytest_ofrak.patterns.pack_unpack_filesystem import FilesystemPackUnpackVerifyPattern

CHILD_TEXT = "Hello World\n"
SUBCHILD_TEXT = "Goodbye World\n"

CHILD_TEXTFILE_NAME = "hello.txt"
CHILD_FOLDER = "test_folder"
SUBCHILD_TEXTFILE_NAME = "goodbye.txt"
SUBCHILD_FOLDER = "test_subfolder"

FIFO_PIPE_NAME = "fifo"
DEVICE_NAME = "device"


class FilesystemRootDirectory(tempfile.TemporaryDirectory):
    """
    Create a root filesystem directory for testing
    """

    def __enter__(self):
        temp_dir = self.name
        child_folder = os.path.join(temp_dir, CHILD_FOLDER)
        child_file = os.path.join(temp_dir, CHILD_TEXTFILE_NAME)

        subchild_file = os.path.join(child_folder, SUBCHILD_TEXTFILE_NAME)
        subchild_folder = os.path.join(child_folder, SUBCHILD_FOLDER)

        if not os.path.exists(child_folder):
            os.mkdir(child_folder)
        if not os.path.exists(subchild_folder):
            os.mkdir(subchild_folder)

        child_fifo = os.path.join(temp_dir, FIFO_PIPE_NAME)
        block_device = os.path.join(temp_dir, DEVICE_NAME)
        if not os.path.exists(child_fifo):
            os.mkfifo(child_fifo)
        if not os.path.exists(block_device):
            os.makedev(1, 2)

        with open(child_file, "w") as f:
            f.write(CHILD_TEXT)
        with open(subchild_file, "w") as f:
            f.write(SUBCHILD_TEXT)
        return temp_dir


@pytest.fixture
async def filesystem_root(ofrak_context: OFRAKContext) -> Resource:
    with FilesystemRootDirectory() as temp_dir:
        resource = await ofrak_context.create_root_resource(
            name=temp_dir, data=b"", tags=[FilesystemRoot]
        )
        filesystem_root = await resource.view_as(FilesystemRoot)
        await filesystem_root.initialize_from_disk(temp_dir)
        yield filesystem_root


class TestFilesystemRoot:
    """
    Test FilesystemRoot methods.
    """

    async def test_initialize_from_disk(self, ofrak_context: OFRAKContext):
        """
        Test that FilesystemRoot.initialize_from_disk modifies a resources tree summary.
        """
        with FilesystemRootDirectory() as temp_dir:
            resource = await ofrak_context.create_root_resource(
                name=temp_dir, data=b"", tags=[FilesystemRoot]
            )
            original_tree = await resource.summarize_tree()
            filesystem_root = await resource.view_as(FilesystemRoot)
            await filesystem_root.initialize_from_disk(temp_dir)
            initialized_tree = await resource.summarize_tree()
            assert original_tree != initialized_tree

    async def test_flush_to_disk(self, ofrak_context: OFRAKContext):
        """
        Test that FilesystemRoot.flush_to_disk correctly flushes the filesystem resources.
        """
        with FilesystemRootDirectory() as temp_dir:
            resource = await ofrak_context.create_root_resource(
                name=temp_dir, data=b"", tags=[FilesystemRoot]
            )
            filesystem_root = await resource.view_as(FilesystemRoot)
            await filesystem_root.initialize_from_disk(temp_dir)

            with tempfile.TemporaryDirectory() as flush_dir:
                await filesystem_root.flush_to_disk(flush_dir)

                diff_directories(temp_dir, flush_dir, extra_diff_flags="")

    async def test_get_entry(self, filesystem_root: FilesystemRoot):
        """
        Test that FilesystemRoot.get_entry returns the correct entry.
        """
        entry = await filesystem_root.get_entry(CHILD_TEXTFILE_NAME)
        assert entry.name == CHILD_TEXTFILE_NAME

    async def test_list_dir(self, filesystem_root: FilesystemRoot):
        """
        Test that FilesystemRoot.list_dir returns the expected directory contents.
        """
        list_dir_output = await filesystem_root.list_dir()
        assert set(list_dir_output.keys()) == {FIFO_PIPE_NAME, CHILD_FOLDER, CHILD_TEXTFILE_NAME}

    async def test_add_folder(self, filesystem_root: FilesystemRoot, tmp_path):
        """
        Test FilesystemRoot.add_folder functionality.
        """
        new_folder_name = "new_folder"
        tmp_dir = tmp_path / new_folder_name
        tmp_dir.mkdir()

        list_dir_output = await filesystem_root.list_dir()
        assert new_folder_name not in list_dir_output.keys()

        await filesystem_root.add_folder(tmp_dir.name, os.stat(tmp_dir))
        updated_list_dir_output = await filesystem_root.list_dir()
        assert new_folder_name in updated_list_dir_output.keys()

    async def test_add_file(self, filesystem_root: FilesystemRoot, tmp_path):
        """
        Test FilesystemRoot.add_file functionality.
        """
        new_file_name = "new_file"
        new_file_bytes = b"New file"
        tmp_file = tmp_path / new_file_name
        tmp_file.write_bytes(new_file_bytes)

        list_dir_output = await filesystem_root.list_dir()
        assert new_file_name not in list_dir_output.keys()

        await filesystem_root.add_file(tmp_file.name, new_file_bytes, os.stat(tmp_file))
        updated_list_dir_output = await filesystem_root.list_dir()
        assert new_file_name in updated_list_dir_output.keys()

    async def test_remove_file(self, filesystem_root: FilesystemRoot):
        """
        Test FilesystemRoot.remove_file functionality.
        """
        list_dir_output = await filesystem_root.list_dir()
        assert CHILD_TEXTFILE_NAME in list_dir_output

        await filesystem_root.remove_file(CHILD_TEXTFILE_NAME)
        updated_list_dir_output = await filesystem_root.list_dir()
        assert CHILD_TEXTFILE_NAME not in updated_list_dir_output


class TestFilesystemEntry:
    """
    Test FilesystemEntry methods.
    """

    async def test_modify_stat_attribute(self, filesystem_root: FilesystemRoot):
        """
        Test that FilesytemEntry.modify_stat_attribute modifies the entry's stat attributes.
        """
        child_textfile = await filesystem_root.get_entry(CHILD_TEXTFILE_NAME)
        new_stat_mode = 0o100755
        assert new_stat_mode != child_textfile.stat.st_mode
        await child_textfile.modify_stat_attribute(stat.ST_MODE, new_stat_mode)
        assert new_stat_mode == child_textfile.stat.st_mode

    async def test_modify_xattr_attribute(self, filesystem_root: FilesystemRoot):
        """
        Test that FilesystemEntry.modify_xattr_attribute modifies the entry's xattr attributes.
        """
        child_textfile = await filesystem_root.get_entry(CHILD_TEXTFILE_NAME)
        assert child_textfile.xattrs == {}
        await child_textfile.modify_xattr_attribute("user.foo", b"bar")
        assert child_textfile.xattrs == {"user.foo": b"bar"}


class TestFolder:
    async def test_get_entry(self, filesystem_root: FilesystemRoot):
        """
        Test Folder.get_entry method.
        """
        folder_entry = await filesystem_root.get_entry(CHILD_FOLDER)
        folder = await folder_entry.resource.view_as(Folder)
        assert await folder.get_entry("Nonexistent") is None
        subchild = await folder.get_entry(SUBCHILD_TEXTFILE_NAME)
        assert subchild.name == SUBCHILD_TEXTFILE_NAME


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
            archive.close()
            command = ["tar", "--xattrs", "-C", directory, "-cf", archive.name, "."]
            subprocess.run(command, check=True, capture_output=True)

            return await ofrak_context.create_root_resource_from_file(archive.name)

    async def unpack(self, root_resource: Resource):
        await root_resource.unpack_recursively()

    async def repack(self, root_resource: Resource):
        await root_resource.pack_recursively()

    async def extract(self, root_resource: Resource, extract_dir: str):
        with tempfile.NamedTemporaryFile(suffix=".tar") as tar:
            data = await root_resource.get_data()
            tar.write(data)
            tar.close()

            command = ["tar", "--xattrs", "-C", extract_dir, "-xf", tar.name]
            subprocess.run(command, check=True, capture_output=True)


class TestLoadInMemoryFilesystem(TestSymbolicLinkUnpackPack):
    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        with tempfile.TemporaryDirectory() as archive_dir:
            archive_name = os.path.join(archive_dir, "archive.tar")
            command = ["tar", "--xattrs", "-C", directory, "-cf", archive_name, "."]
            subprocess.run(command, check=True, capture_output=True)

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


def diff_directories(dir_1, dir_2, extra_diff_flags):
    """
    Diff two directories and assert that their contents are equal.
    """
    # check for diff version > 3.3 (https://unix.stackexchange.com/a/128089)
    diff_version_string = subprocess.check_output(
        "diff --version | head -n1", shell=True, close_fds=True
    )
    diff_version = float(re.findall(r"\d+\.\d+", diff_version_string.decode())[-1])
    assert diff_version >= 3.3

    try:
        _ = subprocess.check_output(
            f"diff --no-dereference --brief {extra_diff_flags} -Nr {dir_1} {dir_2}",
            shell=True,
            close_fds=True,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        # There is an old bug in diff that causes a mismatch if character files are compared,
        # regardless of whether or not they are the same type. Here, we iterate over the output,
        # looking for errors of this form and verifying that the two files are of the same type.
        # Bug: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=126668
        for line in str(e.output).splitlines():
            assert " while " in line

            line.split(" while ")
            first = line[0]
            second = line[1]

            first_type = " ".join(first.split(" ")[4:])
            second_type = " ".join(second.split(" ")[4:])

            assert first_type == second_type
