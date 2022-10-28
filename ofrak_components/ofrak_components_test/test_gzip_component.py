import os
import subprocess
import tempfile
from gzip import GzipFile
from io import BytesIO

import pytest

from ofrak import OFRAKContext
from ofrak.core.filesystem import format_called_process_error
from ofrak.resource import Resource
from ofrak_components.gzip import GzipData
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern


class TestGzipUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    expected_tag = GzipData

    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        d = tmpdir.mkdir("gzip")
        fh = d.join("hello.gz")
        result = BytesIO()
        with GzipFile(fileobj=result, mode="w") as gzip_file:
            gzip_file.write(self.INITIAL_DATA)
        fh.write_binary(result.getvalue())

        self._test_file = fh.realpath()

    async def verify(self, repacked_root_resource: Resource):
        patched_gzip_file = GzipFile(fileobj=BytesIO(await repacked_root_resource.get_data()))
        patched_decompressed_data = patched_gzip_file.read()
        assert patched_decompressed_data == self.EXPECTED_REPACKED_DATA


class TestGzipUnpackWithTrailingBytes(UnpackModifyPackPattern):
    EXPECTED_TAG = GzipData
    INITIAL_DATA = b"Hello World"
    EXPECTED_DATA = INITIAL_DATA  # Change expected when modifier is created
    INNER_FILENAME = "hello.bin"
    GZIP_FILENAME = "hello.bin.gz"

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as d:
            file_path = os.path.join(d, self.INNER_FILENAME)
            with open(file_path, "wb") as f:
                f.write(self.INITIAL_DATA)

            gzip_path = os.path.join(d, self.GZIP_FILENAME)
            gzip_command = ["pigz", file_path]
            try:
                subprocess.run(gzip_command, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(format_called_process_error(e))

            # Add trailing bytes
            with open(gzip_path, "ab") as a:
                a.write(b"\xDE\xAD\xBE\xEF")
                a.close()
            return await ofrak_context.create_root_resource_from_file(gzip_path)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack_recursively()

    async def modify(self, root_resource: Resource) -> None:
        pass

    async def repack(self, root_resource: Resource) -> None:
        pass

    async def verify(self, root_resource: Resource) -> None:
        gzip_data = await root_resource.get_data()
        with tempfile.TemporaryDirectory() as d:
            gzip_path = os.path.join(d, self.GZIP_FILENAME)
            with open(gzip_path, "wb") as f:
                f.write(gzip_data)

            gunzip_command = ["pigz", "-d", "-c", gzip_path]
            try:
                result = subprocess.run(gunzip_command, check=True, capture_output=True)
                data = result.stdout
            except subprocess.CalledProcessError as e:
                if e.returncode == 2 or e.returncode == -2:
                    data = e.stdout
                else:
                    raise RuntimeError(format_called_process_error(e))

            assert data == self.EXPECTED_DATA
