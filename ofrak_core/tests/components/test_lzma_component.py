import lzma

import pytest

from ofrak.resource import Resource
from ofrak.core.lzma import LzmaData, XzData
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


class TestXzUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    expected_tag = XzData

    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        d = tmpdir.mkdir("xz")
        lzma2_file = d.join("hello.xz")
        lz2_path = lzma2_file.realpath()
        lz2_data = lzma.compress(self.INITIAL_DATA, lzma.FORMAT_XZ)
        lzma2_file.write_binary(lz2_data)

        self._test_file = lz2_path

    async def verify(self, repacked_root_resource: Resource):
        patched_data = await repacked_root_resource.get_data()
        patched_decompressed_data = lzma.decompress(patched_data, lzma.FORMAT_XZ)

        assert patched_decompressed_data == self.EXPECTED_REPACKED_DATA


class TestLzmaUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    expected_tag = LzmaData

    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        d = tmpdir.mkdir("lzma")
        lzma1_file = d.join("hello.lzma")
        lz1_path = lzma1_file.realpath()
        lz1_data = lzma.compress(self.INITIAL_DATA, lzma.FORMAT_ALONE)
        lzma1_file.write_binary(lz1_data)

        self._test_file = lz1_path

    async def verify(self, repacked_root_resource: Resource):
        patched_data = await repacked_root_resource.get_data()
        patched_decompressed_data = lzma.decompress(patched_data, lzma.FORMAT_ALONE)

        assert patched_decompressed_data == self.EXPECTED_REPACKED_DATA
