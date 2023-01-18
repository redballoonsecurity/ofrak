import subprocess
import tempfile
from dataclasses import dataclass
import logging
from typing import List
import os

from ofrak import Identifier, Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak.core.filesystem import File
from ofrak.core.binary import GenericBinary
from ofrak.resource_view import ResourceView

from ofrak_type.range import Range

from ubireader import ubi_io
from ubireader.ubi import ubi as ubireader_ubi
from ubireader.ubi.defines import UBI_EC_HDR_MAGIC, UBI_VID_HDR_MAGIC, PRINT_VOL_TYPE_LIST
from ubireader.utils import guess_peb_size

from ofrak.model.resource_model import index

LOGGER = logging.getLogger(__name__)

UBINIZE_TOOL = ComponentExternalTool(
    "ubinize",
    "http://www.linux-mtd.infradead.org/faq/ubi.html#L_ubi_mkimg",
    install_check_arg="--help",
    apt_package="mtd-utils",
    brew_package="",  # This isn't compatible with macos, but there may be an alternative tool to do the bidding.
)


@dataclass
class UbiVolume(ResourceView):
    # mode = ubi
    # image = <filepath to image>
    id: int
    peb_count: int  # size = UbiVolume.peb_count * Ubi.peb_size
    type: str
    name: str
    flag_autoresize: bool # `vol_flags` only specifies an auto-resize flag
    alignment: int

    @index
    def UbiVolumeId(self) -> int:
        return self.id


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
                    PRINT_VOL_TYPE_LIST[volume.vol_rec.vol_type],
                    volume.vol_rec.name.decode('utf-8'),  # TODO support unicode / make tunable?
                    volume.vol_rec.flags,  # Autoresize flag for standard UBI
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

            # extract temp_file to temp_flush_dir
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = [
                    "ubireader_extract_images",
                    "-o",
                    temp_flush_dir,
                    temp_file.name,
                ]
                subprocess.run(command, check=True, capture_output=True)

                ubi_view = await resource.view_as(Ubi)

                # Each file extracted by `ubireader_extract_images` is populated as an UbiVolume
                # `ubireader_extract_images` incorrectly appends a `ubifs` suffix despite unpacking ubi images / volumes
                for vol in ubi_view.volumes:
                    f_path = f"{temp_flush_dir}/{os.path.basename(temp_file.name)}" \
                             f"/img-{ubi_view.image_seq}_vol-{vol.name}.ubifs"
                    with open(f_path, "rb") as f:
                        await resource.create_child_from_view(
                            vol,
                            data=f.read()
                        )


class UbiPacker(Packer[None]):
    """
    Generate an UBI image from an Ubi resource view.
    """

    targets = (Ubi,)
    external_dependencies = (UBINIZE_TOOL,)

    async def pack(self, resource: Resource, config=None) -> None:
        ubi_view = await resource.view_as(Ubi)

        # with tempfile.NamedTemporaryFile(mode="rb") as temp:
        with tempfile.TemporaryDirectory() as temp_flush_dir:
            ubi_volumes = await resource.get_children()
            command = [
                "ubinize",
                "-p",
                str(ubi_view.peb_size),
                "-m",
                str(ubi_view.min_io_size),
                "-o",
                f"{temp_flush_dir}/output.ubi",
                f"{temp_flush_dir}/config.ini"
            ]
            ubinize_ini_entries = []

            for volume in ubi_volumes:
                volume_view = await volume.view_as(UbiVolume)
                volume_size = await volume.get_data_length()
                if volume_size != 0:
                    volume_path = f"{temp_flush_dir}/input-{ubi_view.image_seq}_vol-{volume_view.name}.ubivol"
                    await volume.flush_to_disk(volume_path)
                else:
                    volume_path = None
                    volume_size = (volume_view.peb_count - 1) * ubi_view.peb_size

                ubinize_ini_entry = f"""\
[{volume_view.name}-volume]
mode=ubi
{(f"image={volume_path}" if volume_path else "")}
vol_id={volume_view.id}
vol_size={volume_size}
vol_type={volume_view.type}
vol_name={volume_view.name}
{(f"vol_flags=autoresize" if volume_view.flag_autoresize else "" )}
"""
                ubinize_ini_entries.append(ubinize_ini_entry)

            with open(f"{temp_flush_dir}/config.ini", "w") as config_ini_file:
                config_ini_file.write('\n'.join(ubinize_ini_entries))

            subprocess.run(command, check=True, capture_output=True)

            with open(f"{temp_flush_dir}/output.ubi", "rb") as output_f:
                packed_blob_data = output_f.read()

            resource.queue_patch(Range(0, await resource.get_data_length()), packed_blob_data)


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
