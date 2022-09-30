import os
import subprocess
import tempfile

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import format_called_process_error, FilesystemEntry
from ofrak.resource import Resource
from pytest_ofrak.patterns.pack_unpack_filesystem import FilesystemPackUnpackVerifyPattern


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
