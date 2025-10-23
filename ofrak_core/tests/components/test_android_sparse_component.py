"""
Test the functionality of the Android sparse image component, including unpacking,
modifying, and repacking sparse images.

Requirements Mapping:
- REQ1.3
- REQ4.4

Test Asset Requirements:
=======================
This test requires a real Android sparse image file at tests/components/assets/ext4.4096.simg

To create test assets:
  # Install tools (Ubuntu/Debian)
  sudo apt-get install android-sdk-libsparse-utils

  # Or on macOS
  brew install simg2img

  # Create sparse images from raw files
  img2simg tests/components/assets/ext4.4096.img tests/components/assets/ext4.4096.simg 4096
  img2simg tests/components/assets/random8M tests/components/assets/random8M.simg 2048
"""
import asyncio
from pathlib import Path
from subprocess import CalledProcessError

from ofrak_type.range import Range
import pytest

from ofrak.component.abstract import ComponentSubprocessError
from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.android_sparse import (
    AndroidSparseImage,
    AndroidSparseImagePacker,
    AndroidSparseImageUnpacker,
    SIMG2IMG,
    SPARSE_HEADER_MAGIC,
)
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)

ASSETS_DIR = Path(__file__).parent / "assets"


@pytest.fixture(
    autouse=True,
    scope="module",
    params=[
        (ASSETS_DIR / "ext4.4096.simg", ASSETS_DIR / "ext4.4096.img", ASSETS_DIR / "ext4.2048.img"),
    ],
    ids=["ext4 image"],
)
def android_sparse_test_input(request):
    """
    Fixture providing real test data for Android sparse image tests.

    User must provide real sparse image files at:
    - tests/components/assets/ext4.4096.simg
    - tests/components/assets/ext4.4096.img (raw file)
    - tests/components/assets/ext4.2048.img (raw file)

    :return: Tuple of (sparse_file_path, initial_raw_data, expected_repacked_data)
    """
    sparse_path, initial_path, repacked_path = request.param

    # Load initial and expected data from real files
    with open(initial_path, "rb") as f:
        initial_data = f.read()
    with open(repacked_path, "rb") as f:
        expected_data = f.read()

    return (sparse_path, initial_data, expected_data)


class AndroidSparseUnpackModifyPackPattern(CompressedFileUnpackModifyPackPattern):
    """
    Template for tests that verify Android sparse image unpacking, modification, and repacking.

    This test verifies that:
    - An Android sparse image can be successfully unpacked to raw format
    - Modifications to the unpacked raw data can be applied
    - The modified data can be repacked back into a valid sparse image
    - The sparse image contains the expected data after conversion back to raw
    """

    expected_tag = AndroidSparseImage

    @pytest.fixture(autouse=True)
    def create_test_file(self, android_sparse_test_input, tmp_path: Path):
        """
        Reference real test sparse image file.

        :param android_sparse_test_input: Test data fixture with real files
        :param tmp_path: Temporary directory path
        """
        sparse_path, self.INITIAL_DATA, self.EXPECTED_REPACKED_DATA = android_sparse_test_input
        self._test_file = sparse_path.resolve()

    async def verify(self, repacked_root_resource: Resource):
        """
        Verify that the repacked sparse image contains expected data.

        :param repacked_root_resource: The repacked sparse image resource
        """
        sparse_data = await repacked_root_resource.get_data()

        # Verify it's a valid sparse image
        assert sparse_data[:4] == SPARSE_HEADER_MAGIC

        # Use simg2img to verify if available
        if await SIMG2IMG.is_tool_installed():
            import tempfile312 as tempfile

            with tempfile.NamedTemporaryFile(
                suffix=".simg", delete=False
            ) as sparse_file, tempfile.NamedTemporaryFile(suffix=".img", delete=False) as raw_file:
                sparse_file.write(sparse_data)
                sparse_file.close()
                raw_file.close()

                cmd = ["simg2img", sparse_file.name, raw_file.name]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode == 0:
                    with open(raw_file.name, "rb") as f:
                        raw_data = f.read()
                    assert raw_data == self.EXPECTED_REPACKED_DATA
                else:
                    rc = proc.returncode or -1
                    raise CalledProcessError(rc, cmd, stderr)

    async def modify(self, unpacked_root_resource: Resource):
        resource_to_modify = await unpacked_root_resource.get_only_child()
        current_data = await resource_to_modify.get_data()
        resource_to_modify.queue_patch(
            Range.from_size(0, len(current_data)), self.EXPECTED_REPACKED_DATA
        )
        await resource_to_modify.save()


@pytest.mark.skipif_missing_deps([AndroidSparseImagePacker, AndroidSparseImageUnpacker])
class TestAndroidSparseImageUnpackModifyPack(AndroidSparseUnpackModifyPackPattern):
    """
    Test the basic unpack, modify, and pack functionality for Android sparse images.

    This test requires simg2img tool to be installed and real test assets.
    User must provide: tests/components/assets/hello_world.simg
    """


async def test_sparse_image_identification(ofrak_context: OFRAKContext):
    """
    Test that Android sparse images are correctly identified by magic bytes (REQ1.3).

    This test verifies that:
    - Files with sparse image magic bytes are identified as AndroidSparseImage
    - The MagicIdentifier correctly tags the resource

    User must provide: tests/components/assets/ext4.4096.simg
    """
    sparse_path = ASSETS_DIR / "ext4.4096.simg"

    resource = await ofrak_context.create_root_resource_from_file(str(sparse_path))
    await resource.identify()

    assert resource.has_tag(AndroidSparseImage)


@pytest.mark.skipif_missing_deps([AndroidSparseImagePacker, AndroidSparseImageUnpacker])
async def test_large_sparse_image_roundtrip(ofrak_context: OFRAKContext):
    """
    Test unpacking and repacking of a larger sparse image (REQ4.4).

    This test verifies that:
    - Larger sparse images can be unpacked successfully
    - The unpacked data maintains integrity
    - The data can be repacked into a valid sparse image

    User must provide: tests/components/assets/random8M.simg
    """
    large_sparse = ASSETS_DIR / "random8M.simg"

    # Test unpacking
    resource = await ofrak_context.create_root_resource_from_file(str(large_sparse))

    await resource.unpack()
    child = await resource.get_only_child()
    unpacked_data = await child.get_data()

    # Test repacking
    await resource.pack()
    repacked_data = await resource.get_data()

    # Verify it's a valid sparse image
    assert repacked_data[:4] == SPARSE_HEADER_MAGIC

    # Verify repacked image can be unpacked to same data
    resource2 = await ofrak_context.create_root_resource("repacked.simg", repacked_data)
    await resource2.unpack()
    child2 = await resource2.get_only_child()
    unpacked_data2 = await child2.get_data()

    assert unpacked_data == unpacked_data2


@pytest.mark.skipif_missing_deps([AndroidSparseImagePacker, AndroidSparseImageUnpacker])
async def test_corrupted_sparse_image_fails(ofrak_context: OFRAKContext):
    """
    Test that corrupted sparse images raise appropriate errors.

    This test verifies that:
    - Corrupted sparse image files raise errors when unpacking
    - The error type is appropriate (ComponentSubprocessError or CalledProcessError)

    Test will create a corrupted sparse image data file with valid magic but invalid chunk structure.
    """
    corrupted_data = SPARSE_HEADER_MAGIC + b"\xFF" * 100
    resource = await ofrak_context.create_root_resource("corrupted.simg", corrupted_data)
    await resource.identify()

    # Identification should still work because the magic is valid
    assert resource.has_tag(AndroidSparseImage)

    with pytest.raises((ComponentSubprocessError, CalledProcessError, ValueError)):
        await resource.unpack()


async def test_tool_not_installed():
    """
    Test that _AndroidSparseImageTool.is_tool_installed returns False for non-existent tools.

    This test verifies that:
    - The is_tool_installed method handles FileNotFoundError correctly
    - Returns False when a tool doesn't exist on the system
    """
    from ofrak.core.android_sparse import _AndroidSparseImageTool

    fake_tool = _AndroidSparseImageTool("nonexistent_tool_12345", "fake-package", "fake-brew")
    is_installed = await fake_tool.is_tool_installed()
    assert is_installed is False
