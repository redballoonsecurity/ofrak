"""
Docker image tarball unpacker for OFRAK.

Supports Docker image tarballs created by ``docker save``. Parses the image manifest to determine
layer ordering, extracts each layer in order, and applies Docker whiteouts.
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError
from typing import List

from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.filesystem import File, Folder, SpecialFileType
from ofrak.core.tar import TAR, TarArchive
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource

LOGGER = logging.getLogger(__name__)

_WHITEOUT_PREFIX = ".wh."
_OPAQUE_WHITEOUT = ".wh..wh..opq"


@dataclass
class DockerImage(TarArchive):
    """
    A Docker image saved as a tar archive (from `docker save`).

    Contains layer tarballs and metadata (`manifest.json`) that together describe a container
    filesystem. When unpacked, the layers are applied in order with Docker whiteout semantics to
    reconstruct the final filesystem as it would appear inside a running container.
    """


class DockerImageIdentifier(Identifier):
    """
    Identifies Docker image tarballs by checking for a valid `manifest.json` inside the tar archive.
    """

    targets = (TarArchive,)
    external_dependencies = (TAR,)

    async def identify(self, resource: Resource, config=None) -> None:
        async with resource.temp_to_disk(suffix=".tar") as temp_path:
            cmd = [TAR.tool, "-xf", temp_path, "-O", "manifest.json"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode:
                return

            try:
                manifest = json.loads(stdout.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                return

            if (
                isinstance(manifest, list)
                and len(manifest) > 0
                and isinstance(manifest[0], dict)
                and "Layers" in manifest[0]
                and "Config" in manifest[0]
            ):
                resource.add_tag(DockerImage)


class DockerImageUnpacker(Unpacker[None]):
    """
    Unpacks a Docker image tarball into a single merged filesystem representing the final state of
    the container's root filesystem.

    Parses the image `manifest.json` to determine layer ordering, extracts each layer in sequence,
    and applies Docker whiteout semantics (`.wh.*` deletion markers and `.wh..wh..opq` opaque
    whiteouts) to reconstruct the final container filesystem. Layers are gzip-compressed tar
    archives stored in the ``blobs/sha256/`` directory (OCI layout) or as ``<id>/layer.tar`` files
    (legacy Docker format).
    """

    targets = (DockerImage,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (TAR,)

    async def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        docker_view = await resource.view_as(DockerImage)

        async with resource.temp_to_disk(suffix=".tar") as temp_archive:
            with tempfile.TemporaryDirectory() as extract_dir:
                cmd = [TAR.tool, "-C", extract_dir, "-xf", temp_archive]
                proc = await asyncio.create_subprocess_exec(*cmd)
                returncode = await proc.wait()
                if returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)

                manifest_path = os.path.join(extract_dir, "manifest.json")
                with open(manifest_path, "r") as f:
                    manifest = json.load(f)

                layers = manifest[0]["Layers"]

                with tempfile.TemporaryDirectory() as merged_dir:
                    for layer_path in layers:
                        layer_full_path = os.path.join(extract_dir, layer_path)
                        await self._apply_layer(layer_full_path, merged_dir)

                    await docker_view.initialize_from_disk(merged_dir)

    async def _apply_layer(self, layer_path: str, merged_dir: str) -> None:
        """
        Apply a single layer to the merged filesystem directory.

        Handles opaque whiteouts (clearing directories) before extraction, then extracts the layer
        and processes regular whiteout markers afterward.
        """
        opaque_dirs = await self._find_opaque_whiteouts(layer_path)
        for opaque_dir in opaque_dirs:
            target = os.path.join(merged_dir, opaque_dir)
            if os.path.isdir(target):
                shutil.rmtree(target)
                os.makedirs(target)

        cmd = [TAR.tool, "-C", merged_dir, "-xf", layer_path]
        proc = await asyncio.create_subprocess_exec(*cmd)
        returncode = await proc.wait()
        if returncode:
            raise CalledProcessError(returncode=returncode, cmd=cmd)

        _process_whiteouts(merged_dir)

    async def _find_opaque_whiteouts(self, layer_path: str) -> List[str]:
        """
        Scan a layer tar for opaque whiteout entries before extraction.
        """
        cmd = [TAR.tool, "-tf", layer_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode:
            return []

        opaque_dirs: List[str] = []
        for entry in stdout.decode().splitlines():
            entry = entry.strip("/")
            basename = os.path.basename(entry)
            if basename == _OPAQUE_WHITEOUT:
                parent = os.path.dirname(entry)
                if parent:
                    opaque_dirs.append(parent)
        return opaque_dirs


class DockerImagePacker(Packer[None]):
    """
    Packing a DockerImage back into a layered Docker image tarball is not supported.
    """

    targets = (DockerImage,)

    async def pack(self, resource: Resource, config=None) -> None:
        raise NotImplementedError(
            "Packing a DockerImage back into a Docker image tarball is not supported. "
            "The current unpacker merges all layers into a single filesystem, so the original "
            "layer structure cannot be reconstructed."
        )


def _process_whiteouts(root_dir: str) -> None:
    """
    Remove whiteout markers and their target files/directories.

    Walk bottom-up so that child whiteouts are processed before parent directories.
    """
    for dirpath, _, filenames in os.walk(root_dir, topdown=False):
        for filename in filenames:
            if filename == _OPAQUE_WHITEOUT:
                # Opaque whiteout marker — the directory was already cleared before
                # extraction in _apply_layer; just remove the marker file itself.
                os.remove(os.path.join(dirpath, filename))
            elif filename.startswith(_WHITEOUT_PREFIX):
                # Regular whiteout — remove both the marker and the target
                os.remove(os.path.join(dirpath, filename))
                target_name = filename[len(_WHITEOUT_PREFIX) :]
                target_path = os.path.join(dirpath, target_name)
                if os.path.isdir(target_path) and not os.path.islink(target_path):
                    shutil.rmtree(target_path)
                elif os.path.exists(target_path) or os.path.islink(target_path):
                    os.remove(target_path)
