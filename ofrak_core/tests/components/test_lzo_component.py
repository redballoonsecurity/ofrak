import subprocess

from ofrak.core.lzo import LzoPacker, LzoUnpacker
import pytest

from ofrak.resource import Resource
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


@pytest.mark.skipif_missing_deps([LzoUnpacker, LzoPacker])
class TestLzoUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        d = tmpdir.mkdir("lzo")
        uncompressed_filename = d.join("hello.txt").realpath()
        with open(uncompressed_filename, "wb") as f:
            f.write(self.INITIAL_DATA)

        compressed_filename = d.join("hello.lzo").realpath()
        command = ["lzop", "-o", compressed_filename, uncompressed_filename]
        subprocess.run(command, check=True, capture_output=True)

        self._test_file = compressed_filename

    async def verify(self, repacked_root_resource: Resource) -> None:
        async with repacked_root_resource.temp_to_disk() as temp_path:
            command = ["lzop", "-d", "-f", "-c", temp_path]
            result = subprocess.run(command, check=True, capture_output=True)

            assert result.stdout == self.EXPECTED_REPACKED_DATA
