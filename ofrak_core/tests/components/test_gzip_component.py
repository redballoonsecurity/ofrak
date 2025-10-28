"""
Test the functionality of the gzip component, including unpacking,
modifying, and repacking gzip-compressed data.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import zlib
import gzip
from pathlib import Path
from asyncio import create_subprocess_exec
from typing import Tuple
from unittest.mock import patch
from abc import ABC, abstractmethod

from ofrak.component.abstract import ComponentSubprocessError
import pytest

from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.gzip import GzipData, PIGZ
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)

ASSETS_DIR = Path(__file__).parent / "assets"


@pytest.fixture(
    autouse=True,
    scope="module",
    params=[
        (ASSETS_DIR / "hello_world", ASSETS_DIR / "hello_ofrak", False),
        (ASSETS_DIR / "random8M", ASSETS_DIR / "random8M_modified", True),
    ],
    ids=["hello world", "<random 8MB data>"],
)
def gzip_test_input(request):
    initial_path, repacked_path, expect_pigz = request.param
    with open(initial_path, "rb") as initial_file:
        initial_data = initial_file.read()
    with open(repacked_path, "rb") as repacked_file:
        expected_repacked_data = repacked_file.read()
    return (initial_data, expected_repacked_data, expect_pigz)


class GzipUnpackModifyPackPattern(CompressedFileUnpackModifyPackPattern, ABC):
    """
    Template for tests that test different inputs the gzip component should support
    unpacking.

    This test verifies that:
    - A gzip file can be successfully unpacked
    - Modifications to the unpacked data can be applied
    - The modified data can be repacked back into a valid gzip file
    - The gzip file contains the expected data after decompression
    """

    EXPECT_PIGZ: bool
    expected_tag = GzipData

    @abstractmethod
    def write_gzip(self, gzip_path: Path):
        raise NotImplementedError()

    @pytest.fixture(autouse=True)
    def create_test_file(self, gzip_test_input: Tuple[bytes, bytes, bool], tmp_path: Path):
        self.INITIAL_DATA, self.EXPECTED_REPACKED_DATA, self.EXPECT_PIGZ = gzip_test_input
        gzip_path = tmp_path / "test.gz"
        self.write_gzip(gzip_path)
        self._test_file = gzip_path.resolve()

    async def test_unpack_modify_pack(self, ofrak_context: OFRAKContext):
        """
        Test gzip unpack, modify, and pack workflow with pigz optimization (REQ1.3, REQ4.4).

        This test verifies that:
        - Gzip files are unpacked using the appropriate decompressor
        - Large files trigger pigz parallel compression when available
        - Modified data can be successfully repacked into valid gzip format
        - The repacked data decompresses to the expected modified content
        """
        with patch("asyncio.create_subprocess_exec", wraps=create_subprocess_exec) as mock_exec:
            if self.EXPECT_PIGZ and await PIGZ.is_tool_installed():
                await super().test_unpack_modify_pack(ofrak_context)
                assert any(
                    args[0][0] == "pigz" and args[0][1] == "-c" for args in mock_exec.call_args_list
                )
            else:
                await super().test_unpack_modify_pack(ofrak_context)
                mock_exec.assert_not_called()

    async def verify(self, repacked_root_resource: Resource):
        patched_decompressed_data = gzip.decompress(await repacked_root_resource.get_data())
        assert patched_decompressed_data == self.EXPECTED_REPACKED_DATA


class TestGzipUnpackModifyPack(GzipUnpackModifyPackPattern):
    """
    Test the basic unpack, modify, and pack functionality for a simple gzip file.
    """

    def write_gzip(self, gzip_path: Path):
        with gzip.GzipFile(gzip_path, mode="w") as gzip_file:
            gzip_file.write(self.INITIAL_DATA)


class TestGzipWithMultipleMembersUnpackModifyPack(GzipUnpackModifyPackPattern):
    """
    Test the unpack, modify, and pack functionality for a gzip file with multiple members.
    """

    def write_gzip(self, gzip_path: Path):
        middle = len(self.INITIAL_DATA) // 2
        with gzip.GzipFile(gzip_path, mode="w") as gzip_file:
            gzip_file.write(self.INITIAL_DATA[:middle])

        with gzip.GzipFile(gzip_path, mode="a") as gzip_file:
            gzip_file.write(self.INITIAL_DATA[middle:])


class TestGzipWithTrailingBytesUnpackModifyPack(GzipUnpackModifyPackPattern):
    """
    Test the unpack, modify, and pack functionality for a gzip file with trailing bytes.
    """

    def write_gzip(self, gzip_path: Path):
        with gzip.GzipFile(gzip_path, mode="w") as gzip_file:
            gzip_file.write(self.INITIAL_DATA)

        with open(gzip_path, "ab") as raw_file:
            raw_file.write(b"\xDE\xAD\xBE\xEF")


async def test_corrupted_gzip_fail(
    gzip_test_input: Tuple[bytes, bytes, bool], ofrak_context: OFRAKContext
):
    """
    Test that unpacking a corrupted gzip file raises an appropriate error.

    This test verifies that:
    - A gzip file with invalid data (corrupted) raises an error when attempting to unpack
    - The error type is consistent with expected decompression errors
    """
    initial_data = gzip_test_input[0]
    corrupted_data = bytearray(gzip.compress(initial_data))
    corrupted_data[10] = 255
    resource = await ofrak_context.create_root_resource("corrupted.gz", data=bytes(corrupted_data))
    with pytest.raises((zlib.error, ComponentSubprocessError)):
        await resource.unpack()
