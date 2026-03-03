"""
Tests for the Docker image tarball unpacker.
"""

import os

import pytest

from ofrak import OFRAKContext
from ofrak.core.docker import DockerImage, DockerImageUnpacker
from ofrak.core.filesystem import FilesystemEntry
from ofrak.resource import Resource
from .. import components

pytestmark = pytest.mark.skipif_missing_deps([DockerImageUnpacker])

DOCKER_IMAGE_ASSET = os.path.join(
    components.ASSETS_DIR, "docker-for-ofrak-unpacker.tar"
)


async def _get_all_entries(resource: Resource) -> dict:
    """Return a dict of ``{path: FilesystemEntry}`` for all descendants."""
    result = {}
    descendants = await resource.get_descendants_as_view(FilesystemEntry)
    for entry in descendants:
        path = await entry.get_path()
        result[path] = entry
    return result


@pytest.fixture
async def unpacked_docker_image(ofrak_context: OFRAKContext) -> Resource:
    """
    Docker image tarball built from `Dockerfile_for_ofrak_unpacker` with:
    - docker build -t docker-for-ofrak-unpacker -f Dockerfile_for_ofrak_unpacker .
    - docker save docker-for-ofrak-unpacker > docker-for-ofrak-unpacker.tar

    Expected final filesystem state after layer merging:
    - /dir1/file1 exists, containing "hello world 1\\n"
    - /dir2/ exists as empty directory (file2 deleted by whiteout)
    - /dir3 does NOT exist (deleted by directory whiteout)
    - /dir4/file4 exists, containing "hello world 4\\n" (opaque whiteout replaced dir)
    - busybox base layer files present (e.g. /bin/sh)
    """
    asset_path = DOCKER_IMAGE_ASSET
    with open(asset_path, "rb") as f:
        data = f.read()
    resource = await ofrak_context.create_root_resource("docker-for-ofrak-unpacker.tar", data)
    await resource.identify()
    await resource.unpack()
    return resource


class TestDockerImageIdentification:
    async def test_identify_docker_image(self, ofrak_context: OFRAKContext):
        with open(DOCKER_IMAGE_ASSET, "rb") as f:
            data = f.read()
        resource = await ofrak_context.create_root_resource("docker.tar", data)
        await resource.identify()
        assert resource.has_tag(DockerImage)


class TestDockerImageUnpacker:
    async def test_file_from_run_layer_exists(self, unpacked_docker_image: Resource):
        entries = await _get_all_entries(unpacked_docker_image)
        assert "dir1/file1" in entries
        data = await entries["dir1/file1"].resource.get_data()
        assert data == b"hello world 1\n"

    async def test_directory_whiteout(self, unpacked_docker_image: Resource):
        entries = await _get_all_entries(unpacked_docker_image)
        assert not any(p == "dir3" or p.startswith("dir3/") for p in entries)

    async def test_file_whiteout(self, unpacked_docker_image: Resource):
        entries = await _get_all_entries(unpacked_docker_image)
        assert "dir2" in entries
        assert entries["dir2"].is_folder()
        assert "dir2/file2" not in entries

    async def test_opaque_whiteout(self, unpacked_docker_image: Resource):
        entries = await _get_all_entries(unpacked_docker_image)
        assert "dir4/file4" in entries
        data = await entries["dir4/file4"].resource.get_data()
        assert data == b"hello world 4\n"

    async def test_busybox_base_layer_present(self, unpacked_docker_image: Resource):
        entries = await _get_all_entries(unpacked_docker_image)
        assert "bin" in entries

    async def test_no_whiteout_markers_in_output(self, unpacked_docker_image: Resource):
        entries = await _get_all_entries(unpacked_docker_image)
        wh_entries = [p for p in entries if ".wh." in p]
        assert wh_entries == [], f"Whiteout markers not cleaned up: {wh_entries}"
