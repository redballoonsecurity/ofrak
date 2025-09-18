import zlib

import pytest

from ofrak.resource import Resource
from ofrak.core.zlib import ZlibData
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


class TestZlibUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    expected_tag = ZlibData

    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        d = tmpdir.mkdir("zlib")
        _file = d.join("hello.zlib")
        compression_level = 6
        compressed_data = zlib.compress(self.INITIAL_DATA, compression_level)
        with open(_file, "wb") as fh:
            fh.write(compressed_data)
        self._test_file = _file.realpath()

    async def verify(self, repacked_root_resource: Resource):
        patched_data = await repacked_root_resource.get_data()
        patched_decompressed_data = zlib.decompress(patched_data)
        assert patched_decompressed_data == self.EXPECTED_REPACKED_DATA
