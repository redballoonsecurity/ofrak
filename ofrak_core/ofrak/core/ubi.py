import asyncio
import tempfile
from dataclasses import dataclass
import logging
from typing import List, Tuple
import os
from subprocess import CalledProcessError

from ofrak.model.tag_model import ResourceTag

from ofrak import Identifier, Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak.core.filesystem import File
from ofrak.core.binary import GenericBinary
from ofrak.resource_view import ResourceView

from ofrak_type.range import Range

try:
    from ubireader import ubi_io
    from ubireader.ubi import ubi as ubireader_ubi
    from ubireader.ubi.defines import UBI_EC_HDR_MAGIC, UBI_VID_HDR_MAGIC, PRINT_VOL_TYPE_LIST
    from ubireader.utils import guess_peb_size
except ModuleNotFoundError:
    pass

from ofrak.model.resource_model import index

LOGGER = logging.getLogger(__name__)

UBINIZE_TOOL = ComponentExternalTool(
    "ubinize",
    "http://www.linux-mtd.infradead.org/faq/ubi.html#L_ubi_mkimg",
    install_check_arg="--help",
    apt_package="mtd-utils",
    brew_package="",  # This isn't compatible with macos, but there may be an alternative tool to do the bidding.
)


class _PyLzoTool(ComponentExternalTool):
    def __init__(self):
        super().__init__(
            "python-lzo",
            "https://github.com/jd-boyd/python-lzo",
            install_check_arg="",
        )

    async def is_tool_installed(self) -> bool:
        try:
            import lzo  # type: ignore

            return True
        except ModuleNotFoundError:
            return False


PY_LZO_TOOL = _PyLzoTool()


@dataclass
class UbiVolume(ResourceView):
    """
    An UbiVolume is a volume entry in UBI. It contains an image of arbitrary data, typically a filesystem or a
    log. Empty UbiVolumes can still reserve physical erase blocks, in case they are expected to grow.

    Volume information reflected in the 'config.ini' UBI volume entries expected by `ubinize` are stored here. Also see:
    http://www.linux-mtd.infradead.org/faq/ubi.html#L_ubi_mkimg

    :var id: The assigned volume ID within the UBI image
    :var peb_count: Number of PEBs allocated for the volume
    :var type: UBI volume type, either 'static' or 'dynamic'; see http://www.linux-mtd.infradead.org/doc/ubi.html#L_overview
    :var name: Label assigned to the volume
    :var flag_autoresize: Tells UBI to resize this volume to occupy unused space in the UBI image once; see http://www.linux-mtd.infradead.org/doc/ubi.html#L_autoresize
    :var alignment: LEB size of this volume has to be aligned on, such that Ubi.leb_size % UbiVolume.alignment == 0; see https://elixir.bootlin.com/linux/v6.1.7/source/include/uapi/mtd/ubi-user.h#L328
    """

    id: int
    peb_count: int  # size = UbiVolume.peb_count * Ubi.peb_size
    type: str
    name: str
    flag_autoresize: bool  # `vol_flags` only specifies an auto-resize flag
    alignment: int

    @index
    def UbiVolumeId(self) -> int:
        return self.id


@dataclass
class Ubi(GenericBinary):
    """
    UBI is a volume management layer for raw / unmanaged flash devices. It can be thought of LVM
    (Logical Volume Manager) with some additional features necessary for reliably using raw flash memory such as wear
    leveling and error correction. Each volume can contain any arbitrary data, though UBIFS is specially made to be used
    within an UBI volume.

    UBI parameters and volumes required by `ubinize` for repacking are defined here. Also see:
    http://www.linux-mtd.infradead.org/doc/ubi.html and
    https://github.com/vamanea/mtd-utils/blob/master/ubi-utils/ubinize.c#L288`

    :var min_io_size: Minimum number of bytes per I/O transaction (see http://www.linux-mtd.infradead.org/doc/ubi.html#L_min_io_unit)
    :var leb_size: Size of Logical Erase Blocks
    :var peb_size: Size of Physical Erase Blocks
    :var total_peb_count: The total number of PEBs, which includes hidden layout blocks in addition to data blocks allocated per volume
    :var image_seq: image sequence number recorded on EC headers (typically random)
    :var volumes: List of volumes associated with the UBI image
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

    external_dependencies = (PY_LZO_TOOL,)

    async def analyze(self, resource: Resource, config=None) -> Ubi:
        # Flush to disk
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

        # Technically multiple images can be encountered in an UBI blob, but that should be handled by
        # OFRAK by treating them as separate UBI resources.
        if len(ubi_obj.images) > 1:
            raise Exception(
                "Multi-image UBI blobs are not directly supported. Carve each image into a separate "
                "resource and run UbiAnalyzer on each of them."
            )
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
                    volume.vol_rec.name.decode("utf-8"),
                    volume.vol_rec.flags,  # Autoresize flag for standard UBI
                    volume.vol_rec.alignment,
                )
            )

        return Ubi(
            ubi_obj.min_io_size,
            ubi_obj.leb_size,
            ubi_obj.peb_size,
            ubi_obj.block_count,
            image.image_seq,
            ubi_image_vols,
        )


class UbiUnpacker(Unpacker[None]):
    """
    Extract the UBI image
    """

    targets = (Ubi,)
    children = (UbiVolume,)
    external_dependencies = (PY_LZO_TOOL,)

    async def unpack(self, resource: Resource, config=None):
        with tempfile.TemporaryDirectory() as temp_flush_dir:
            # flush to disk
            with open(f"{temp_flush_dir}/input.img", "wb") as temp_file:
                resource_data = await resource.get_data()
                temp_file.write(resource_data)
                temp_file.flush()

            # extract temp_file to temp_flush_dir
            cmd = [
                "ubireader_extract_images",
                "-o",
                f"{temp_flush_dir}/output",
                temp_file.name,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
            )
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)

            ubi_view = await resource.view_as(Ubi)

            # Each file extracted by `ubireader_extract_images` is populated as an UbiVolume
            # `ubireader_extract_images` incorrectly appends a `ubifs` suffix despite unpacking ubi images / volumes
            for vol in ubi_view.volumes:
                f_path = (
                    f"{temp_flush_dir}/output/{os.path.basename(temp_file.name)}"
                    f"/img-{ubi_view.image_seq}_vol-{vol.name}.ubifs"
                )
                with open(f_path, "rb") as f:
                    data = f.read()
                    if len(data) > 0:
                        other_tags: Tuple[ResourceTag, ...] = (GenericBinary,)
                    else:
                        other_tags = ()
                    await resource.create_child_from_view(
                        vol, data=data, additional_tags=other_tags
                    )


class UbiPacker(Packer[None]):
    """
    Generate an UBI image from an Ubi resource view.
    """

    targets = (Ubi,)
    external_dependencies = (UBINIZE_TOOL, PY_LZO_TOOL)

    async def pack(self, resource: Resource, config=None) -> None:
        ubi_view = await resource.view_as(Ubi)

        # with tempfile.NamedTemporaryFile(mode="rb") as temp:
        with tempfile.TemporaryDirectory() as temp_flush_dir:
            ubi_volumes = await resource.get_children()
            ubinize_ini_entries = []

            for volume in ubi_volumes:
                volume_view = await volume.view_as(UbiVolume)
                volume_size = await volume.get_data_length()

                # I think the `ubinize` rounds up the number of required PEBs based on the provided size.
                # Maybe this? allocated PEBs = -(volume_size // -peb_size) + 1
                # For empty volumes I reverse this operation
                if volume_size != 0:
                    volume_path = (
                        f"{temp_flush_dir}/input-{ubi_view.image_seq}_vol-{volume_view.name}.ubivol"
                    )
                    await volume.flush_to_disk(volume_path)
                else:
                    volume_path = None
                    volume_size = (volume_view.peb_count - 1) * ubi_view.peb_size

                # Generate a volume entry for `ubinize`'s config.ini
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
                config_ini_file.write("\n".join(ubinize_ini_entries))

            cmd = [
                "ubinize",
                "-p",
                str(ubi_view.peb_size),
                "-m",
                str(ubi_view.min_io_size),
                "-o",
                f"{temp_flush_dir}/output.ubi",
                f"{temp_flush_dir}/config.ini",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
            )
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)

            with open(f"{temp_flush_dir}/output.ubi", "rb") as output_f:
                packed_blob_data = output_f.read()

            resource.queue_patch(Range(0, await resource.get_data_length()), packed_blob_data)


class UbiIdentifier(Identifier):
    """
    Check the first four bytes of a resource and tag the resource as Ubi if it matches the file magic.
    """

    targets = (File, GenericBinary)

    external_dependencies = (PY_LZO_TOOL,)

    async def identify(self, resource: Resource, config=None) -> None:
        datalength = await resource.get_data_length()
        if datalength >= 4:
            data = await resource.get_data(Range(0, 4))
            if data in [UBI_EC_HDR_MAGIC, UBI_VID_HDR_MAGIC]:
                resource.add_tag(Ubi)
