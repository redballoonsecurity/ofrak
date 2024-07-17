from gzip import GzipFile
from io import BytesIO
from pathlib import Path

import pytest

from ofrak.resource import Resource
from ofrak.core.gzip import GzipData
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


class GzipUnpackModifyPackPattern(CompressedFileUnpackModifyPackPattern):
    """Template for tests that test different inputs the gzip component should support
    unpacking."""

    expected_tag = GzipData

    def write_gzip(self, gzip_path: Path):
        raise NotImplementedError

    @pytest.fixture(autouse=True)
    def create_test_file(self, tmp_path: Path):
        gzip_path = tmp_path / "hello.gz"
        self.write_gzip(gzip_path)
        self._test_file = gzip_path.resolve()

    async def verify(self, repacked_root_resource: Resource):
        patched_gzip_file = GzipFile(fileobj=BytesIO(await repacked_root_resource.get_data()))
        patched_decompressed_data = patched_gzip_file.read()
        assert patched_decompressed_data == self.EXPECTED_REPACKED_DATA


class TestGzipUnpackModifyPack(GzipUnpackModifyPackPattern):
    def write_gzip(self, gzip_path: Path):
        with GzipFile(gzip_path, mode="w") as gzip_file:
            gzip_file.write(self.INITIAL_DATA)


class TestGzipWithMultipleMembersUnpackModifyPack(GzipUnpackModifyPackPattern):
    def write_gzip(self, gzip_path: Path):
        with GzipFile(gzip_path, mode="w") as gzip_file:
            middle = len(self.INITIAL_DATA) // 2
            gzip_file.write(self.INITIAL_DATA[:middle])
            gzip_file.write(self.INITIAL_DATA[middle:])


class TestGzipWithTrailingBytesUnpackModifyPack(GzipUnpackModifyPackPattern):
    def write_gzip(self, gzip_path: Path):
        with GzipFile(gzip_path, mode="w") as gzip_file:
            gzip_file.write(self.INITIAL_DATA)

        with open(gzip_path, "ab") as raw_file:
            raw_file.write(b"\xDE\xAD\xBE\xEF")
