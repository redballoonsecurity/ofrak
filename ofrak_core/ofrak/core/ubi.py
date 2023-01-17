import subprocess
import tempfile
from dataclasses import dataclass
import logging
from typing import List
import os

from ofrak import Identifier, Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.binary import GenericBinary
from ofrak.resource_view import ResourceView

from ofrak_type.range import Range

from ubireader import ubi_io
from ubireader.ubi import ubi as ubireader_ubi
from ubireader.ubi.defines import UBI_EC_HDR_MAGIC, UBI_VID_HDR_MAGIC
from ubireader.utils import guess_leb_size, guess_peb_size

LOGGER = logging.getLogger(__name__)


@dataclass
class UbiVolume(ResourceView):
    # mode = ubi
    # image = <filepath to image>
    id: int
    peb_count: int  # size = UbiVolume.peb_count * Ubi.peb_size
    type: str
    name: str
    flags: str
    alignment: int


@dataclass
class Ubi(GenericBinary):
    """
    http://www.linux-mtd.infradead.org/doc/ubi.html
    """

    min_io_size: int
    leb_size: int
    peb_size: int
    total_peb_count: int  # total_peb_count usually adds 2 layout blocks in addition to data blocks allocated per volume

    # Each UBI image emitted by `ubireader` would be treated as a separate Ubi resource.
    image_seq: int
    volumes: List[UbiVolume]


class UbiAnalyzer(Analyzer[None, Ubi]):
    """
    Extract UBI parameters required for packing a resource.
    """

    targets = (Ubi,)
    outputs = (Ubi,)

    async def analyze(self, resource: Resource, config=None) -> Ubi:
        with tempfile.NamedTemporaryFile() as temp_file:
            resource_data = await resource.get_data()
            temp_file.write(resource_data)
            temp_file.flush()

            ubi_obj = ubireader_ubi(
                ubi_io.ubi_file(
                    temp_file.name,
                    block_size=guess_peb_size(temp_file.name),
                    start_offset=0,
                    end_offset=None,
                )
            )

        if len(ubi_obj.images) > 1:
            raise Exception("Multi-image UBI blobs are not directly supported. Carve each image into a separate "
                            "resource and run UbiAnalyzer on each of them.")
        if len(ubi_obj.images) == 0:
            raise Exception("UBI resource does not have any images.")

        image = ubi_obj.images[0]
        ubi_image_vols: List[UbiVolume] = []
        for volume in image.volumes.values():
            ubi_image_vols.append(
                UbiVolume(
                    volume.vol_rec.rec_index,
                    volume.vol_rec.reserved_pebs,
                    volume.vol_rec.vol_type,
                    volume.vol_rec.name,
                    volume.vol_rec.flags,
                    volume.vol_rec.alignment
                )
            )

        return Ubi(
            ubi_obj.min_io_size,
            ubi_obj.leb_size,
            ubi_obj.peb_size,
            ubi_obj.block_count,
            image.image_seq,
            ubi_image_vols
        )


class UbiUnpacker(Unpacker[None]):
    """
    Extract the UBI image
    """

    targets = (Ubi,)
    children = (UbiVolume,)
    external_dependencies = ()

    async def unpack(self, resource: Resource, config=None):
        with tempfile.NamedTemporaryFile() as temp_file:
            # flush to disk
            resource_data = await resource.get_data()
            temp_file.write(resource_data)
            temp_file.flush()

            # extract temp_file to temp dir
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = [
                    "ubireader_extract_images",
                    "-o",
                    temp_flush_dir,
                    temp_file.name,
                ]
                subprocess.run(command, check=True, capture_output=True)

                # read extracted files
                ubi_view = await resource.view_as(Ubi)

                ###

                for vol in ubi_view.volumes:
                    f_path = f"{temp_flush_dir}/{os.path.basename(temp_file.name)}/img-{ubi_view.image_seq}_vol-{vol.name.decode('utf-8')}.ubifs"
                    print(f"path is: {f_path}")
                    with open(f_path, "rb") as f:
                        await resource.create_child(
                            tags=(UbiVolume,File),
                            data=f.read()
                        )



class UbiPacker(Packer[None]):
    """
    Generate an UBI image from an Ubi resource view.
    """

    targets = (Ubi,)
    external_dependencies = ()

    async def pack(self, resource: Resource, config=None) -> None:
        print("Pretending to pack...")
        pass


class UbiIdentifier(Identifier):
    """
    Check the first four bytes of a resource and tag the resource as Ubi if it matches the file magic.
    """

    targets = (File, GenericBinary)

    async def identify(self, resource: Resource, config=None) -> None:
        datalength = await resource.get_data_length()
        if datalength >= 4:
            data = await resource.get_data(Range(0, 4))
            if data in [UBI_EC_HDR_MAGIC, UBI_VID_HDR_MAGIC]:
                resource.add_tag(Ubi)