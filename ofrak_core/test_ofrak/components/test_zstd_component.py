import subprocess
from ofrak import tempfile

import pytest

from ofrak.resource import Resource
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


class TestZstdUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        d = tmpdir.mkdir("zstd")
        uncompressed_filename = d.join("hello.txt").realpath()
        with open(uncompressed_filename, "wb") as f:
            f.write(self.INITIAL_DATA)

        compressed_filename = d.join("hello.zstd").realpath()
        command = ["zstd", "-19", uncompressed_filename, "-o", compressed_filename]
        subprocess.run(command, check=True, capture_output=True)

        self._test_file = compressed_filename

    async def verify(self, repacked_root_resource: Resource) -> None:
        compressed_data = await repacked_root_resource.get_data()
        with tempfile.NamedTemporaryFile(suffix=".zstd") as compressed_file:
            compressed_file.write(compressed_data)
            compressed_file.close()
            output_filename = tempfile.mktemp()

            command = ["zstd", "-d", "-k", compressed_file.name, "-o", output_filename]
            subprocess.run(command, check=True, capture_output=True)
            with open(output_filename, "rb") as f:
                result = f.read()

            assert result == self.EXPECTED_REPACKED_DATA
