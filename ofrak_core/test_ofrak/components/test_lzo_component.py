import subprocess
from ofrak import tempfile

import pytest

from ofrak.resource import Resource
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


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
        compressed_data = await repacked_root_resource.get_data()
        with tempfile.NamedTemporaryFile(suffix=".lzo") as compressed_file:
            compressed_file.write(compressed_data)
            compressed_file.close()

            command = ["lzop", "-d", "-f", "-c", compressed_file.name]
            result = subprocess.run(command, check=True, capture_output=True)

            assert result.stdout == self.EXPECTED_REPACKED_DATA
