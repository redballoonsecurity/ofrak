import os
import subprocess
from ofrak import tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.component.unpacker import UnpackerError
from ofrak.resource import Resource
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from ofrak.core.tar import TarArchive
from pytest_ofrak.patterns.pack_unpack_filesystem import (
    FilesystemPackUnpackVerifyPattern,
)
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
import test_ofrak.components


class TestTarSingleFileUnpackModifyPack(UnpackModifyPackPattern):
    INITIAL_DATA = b"hello world"
    EXPECTED_DATA = b"hello ofrak"
    INNER_FILENAME = "hello.txt"
    ARCHIVE_FILENAME = "hello.tar"

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as d:
            file_path = os.path.join(d, self.INNER_FILENAME)
            with open(file_path, "wb") as f:
                f.write(self.INITIAL_DATA)

            archive_path = os.path.join(d, self.ARCHIVE_FILENAME)
            command = ["tar", "-cf", archive_path, "-C", d, self.INNER_FILENAME]
            subprocess.run(command, check=True, capture_output=True)

            return await ofrak_context.create_root_resource_from_file(archive_path)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack_recursively()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        tar_view = await unpacked_root_resource.view_as(TarArchive)
        child_textfile = await tar_view.get_entry(self.INNER_FILENAME)
        string_config = StringPatchingConfig(6, "ofrak")
        await child_textfile.resource.run(StringPatchingModifier, string_config)

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.pack_recursively()

    async def verify(self, repacked_root_resource: Resource) -> None:
        patched_data = await repacked_root_resource.get_data()
        with tempfile.TemporaryDirectory() as d:
            archive_path = os.path.join(d, "result.tar")
            with open(archive_path, "wb") as f:
                f.write(patched_data)

            command = ["tar", "-C", d, "-xf", archive_path]
            subprocess.run(command, check=True, capture_output=True)

            result_file_path = os.path.join(d, self.INNER_FILENAME)
            with open(result_file_path, "rb") as f:
                assert self.EXPECTED_DATA == f.read()


class TestTarUnpackerDirectoryTraversalFailure:
    """
    Tar archives can have relative paths like "../file.txt" for files in the archive. This is
    both a security risk and a practical complication. By default on MacOS and some (most?)
    versions of Linux, the tar command will fail on archives containing files with such paths.

    This test validates the desired failure behavior.
    """

    INITIAL_DATA = b"hello world"
    INNER_FILENAME = "hello.txt"
    ARCHIVE_FILENAME = "hello.tar"

    async def test_unpack_fails(self, ofrak_context: OFRAKContext):
        """
        Create a root resource for a tar containing a file located up a directory, and assert
        that unpacking it fails.
        """
        with tempfile.TemporaryDirectory() as d:
            file_path = os.path.join(d, self.INNER_FILENAME)
            with open(file_path, "wb") as f:
                f.write(self.INITIAL_DATA)

            inner_dir = os.path.join(d, "temp")
            os.mkdir(inner_dir)

            archive_path = os.path.join(d, self.ARCHIVE_FILENAME)
            command = [
                "tar",
                "-P",  # Force tar to use the relative path
                "-cf",
                archive_path,
                "-C",
                inner_dir,
                os.path.join("..", self.INNER_FILENAME),
            ]
            subprocess.run(command, check=True, capture_output=True)

            root_resource = await ofrak_context.create_root_resource_from_file(archive_path)

        with pytest.raises(UnpackerError):
            await root_resource.unpack_recursively()


class TestTarFilesystemUnpackRepack(FilesystemPackUnpackVerifyPattern):
    def setup(self):
        super().setup()
        # Don't compare stat values since several entries (like time modified) will be unequal
        # TODO: Fix to compare stat values?
        self.check_stat = False

    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
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


class TestTarNestedUnpackModifyPack(UnpackModifyPackPattern):
    """
    Test a tar within a tar within a tar, and so on... nested several levels deep.
    """

    INITIAL_DATA = b"hello world"
    EXPECTED_DATA = b"hello ofrak"
    INNER_FILENAME = "hello.txt"
    LEVELS = 5  # Must be >= 2

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as d:
            file_path = os.path.join(d, self.INNER_FILENAME)
            with open(file_path, "wb") as f:
                f.write(self.INITIAL_DATA)

            archive_path = ""
            assert self.LEVELS >= 2
            for i in range(self.LEVELS):
                archive_path = os.path.join(d, f"hello_{i}.tar")
                command = [
                    "tar",
                    "-cf",
                    archive_path,
                    "-C",
                    d,
                    self.INNER_FILENAME if i == 0 else f"hello_{i - 1}.tar",
                ]
                subprocess.run(command, check=True, capture_output=True)

            return await ofrak_context.create_root_resource_from_file(archive_path)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack_recursively()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        child = unpacked_root_resource
        # unpacked_root_resource is the first child of the top-level tar, so we have (self.LEVELS
        # - 1) remaining children to traverse to get to the innermost archive
        for _ in range(self.LEVELS - 1):
            child = await child.get_only_child()

        tar_view = await child.view_as(TarArchive)
        child_textfile = await tar_view.get_entry(self.INNER_FILENAME)
        string_config = StringPatchingConfig(6, "ofrak")
        await child_textfile.resource.run(StringPatchingModifier, string_config)

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.pack_recursively()

    async def verify(self, repacked_root_resource: Resource) -> None:
        patched_data = await repacked_root_resource.get_data()
        with tempfile.TemporaryDirectory() as d:
            archive_path = os.path.join(d, f"hello_{self.LEVELS - 1}.tar")
            with open(archive_path, "wb") as f:
                f.write(patched_data)

            for i in range(self.LEVELS - 1, -1, -1):
                command = ["tar", "-C", d, "-xf", os.path.join(d, f"hello_{i}.tar")]
                subprocess.run(command, check=True, capture_output=True)

            result_file_path = os.path.join(d, self.INNER_FILENAME)
            with open(result_file_path, "rb") as f:
                assert self.EXPECTED_DATA == f.read()


class TestComplexTarWithSpecialFiles(FilesystemPackUnpackVerifyPattern):
    def setup(self):
        super().setup()
        self.check_stat = False
        self.testtar_path = os.path.join(test_ofrak.components.ASSETS_DIR, "testtar.tar")

    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        return await ofrak_context.create_root_resource_from_file(self.testtar_path)

    def create_local_file_structure(self, root: str):
        command = ["tar", "--xattrs", "-C", root, "-xf", self.testtar_path]
        subprocess.run(command, check=True, capture_output=True)

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
