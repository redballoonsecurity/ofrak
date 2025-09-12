import subprocess
import tempfile312 as tempfile

from ofrak.core.zstd import ZstdUnpacker, ZstdPacker
import pytest

from ofrak.resource import Resource
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


@pytest.mark.skipif_missing_deps([ZstdUnpacker, ZstdPacker])
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
        async with repacked_root_resource.temp_to_disk(suffix=".zstd") as compressed_file_path:
            output_filename = tempfile.mktemp()

            command = ["zstd", "-d", "-k", compressed_file_path, "-o", output_filename]
            subprocess.run(command, check=True, capture_output=True)
            with open(output_filename, "rb") as f:
                result = f.read()

            assert result == self.EXPECTED_REPACKED_DATA
