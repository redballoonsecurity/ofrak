import asyncio
import logging
import os
from ofrak import tempfile
from dataclasses import dataclass
from io import BytesIO
from subprocess import CalledProcessError
from typing import Iterable, Optional

from pycdlib import PyCdlib

from ofrak.component.analyzer import Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, File, Folder
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.resource_model import index
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter
from ofrak_type import NotFoundError
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ISO9660ImageAttributes(ResourceAttributes):
    interchange_level: int
    volume_identifier: str
    system_identifier: str
    app_identifier: str
    extended_attributes: bool
    has_joliet: bool
    has_rockridge: bool
    has_udf: bool
    has_eltorito: bool
    joliet_level: Optional[int] = None
    rockridge_version: Optional[str] = None
    udf_version: Optional[str] = None


@dataclass
class ISO9660Entry(ResourceView):
    name: str
    path: str
    is_dir: bool
    is_file: bool
    is_symlink: bool
    is_dot: bool
    is_dotdot: bool
    iso_version: int

    @index
    def Path(self) -> str:
        return self.path

    @index
    def Name(self) -> str:
        return self.name


@dataclass
class ISO9660Image(GenericBinary, FilesystemRoot):
    """
    ISO 9660 image. ISO 9660 is a file system for optical disc media.
    """

    async def get_file(self, path: str) -> ResourceView:
        return await self.resource.get_only_descendant_as_view(
            ISO9660Entry,
            r_filter=ResourceFilter(
                attribute_filters=(ResourceAttributeValueFilter(ISO9660Entry.Path, path),)
            ),
        )

    async def get_entries(self) -> Iterable[ISO9660Entry]:
        return await self.resource.get_descendants_as_view(
            ISO9660Entry, r_filter=ResourceFilter(tags=(ISO9660Entry,))
        )


@dataclass
class JolietISO9660Image(ISO9660Image):
    pass


@dataclass
class UdfISO9660Image(ISO9660Image):
    pass


@dataclass
class RockRidgeISO9660Image(ISO9660Image):
    pass


@dataclass
class ElToritoISO9660Image(ISO9660Image):
    pass


class ISO9660ImageAnalyzer(Analyzer[None, ISO9660ImageAttributes]):
    targets = (ISO9660Image,)
    outputs = (ISO9660ImageAttributes,)

    async def analyze(self, resource: Resource, config=None):
        joliet_level = None
        rockridge_version = None
        udf_version = None

        iso = PyCdlib()
        iso.open_fp(BytesIO(await resource.get_data()))

        interchange_level = iso.interchange_level
        has_joliet = iso.has_joliet()
        has_rockridge = iso.has_rock_ridge()
        has_udf = iso.has_udf()
        has_eltorito = iso.eltorito_boot_catalog is not None
        vol_identifier = iso.pvd.volume_identifier.decode("utf-8").strip()
        sys_identifier = iso.pvd.system_identifier.decode("utf-8").strip()
        app_identifier = iso.pvd.application_identifier.text.decode("utf-8").strip()
        xa = iso.xa

        if has_joliet:
            esc = iso.joliet_vd.escape_sequences
            if b"%/@" in esc:
                joliet_level = 1
            elif b"%/C" in esc:
                joliet_level = 2
            elif b"%/E" in esc:
                joliet_level = 3
        elif has_rockridge:
            rockridge_version = iso.rock_ridge
        elif has_udf:
            udf_version = "2.60"

        iso.close()

        return ISO9660ImageAttributes(
            interchange_level=interchange_level,
            volume_identifier=vol_identifier,
            system_identifier=sys_identifier,
            app_identifier=app_identifier,
            extended_attributes=xa,
            has_joliet=has_joliet,
            joliet_level=joliet_level,
            has_rockridge=has_rockridge,
            rockridge_version=rockridge_version,
            has_udf=has_udf,
            udf_version=udf_version,
            has_eltorito=has_eltorito,
        )


class ISO9660Unpacker(Unpacker[None]):
    """
    Unpack an ISO 9660 image.
    """

    id = b"ISO9660Unpacker"
    targets = (ISO9660Image,)
    children = (ISO9660Entry,)

    async def unpack(self, resource: Resource, config=None):
        iso_data = await resource.get_data()

        iso_attributes = await resource.analyze(ISO9660ImageAttributes)
        resource.add_attributes(iso_attributes)
        iso_resource = await resource.view_as(ISO9660Image)

        iso = PyCdlib()
        iso.open_fp(BytesIO(iso_data))

        if iso_attributes.has_joliet:
            facade = iso.get_joliet_facade()
            path_var = "joliet_path"
        elif iso_attributes.has_udf:
            LOGGER.warning("UDF images are not currently supported")
            facade = iso.get_udf_facade()
            path_var = "udf_path"
        elif iso_attributes.has_rockridge:
            LOGGER.warning("Rock Ridge images are not currently supported")
            facade = iso.get_rock_ridge_facade()
            path_var = "rr_name"
        else:
            facade = iso.get_iso9660_facade()
            path_var = "iso_path"

        if iso_attributes.has_eltorito:
            LOGGER.warning("El Torito images are not currently supported")

        for root, dirs, files in iso.walk(**{path_var: "/"}):
            for d in dirs:
                path = os.path.join(root, d)
                folder_tags = (ISO9660Entry, Folder)
                entry = ISO9660Entry(
                    name=d,
                    path=path,
                    is_dir=True,
                    is_file=False,
                    is_symlink=False,
                    is_dot=(str(d).startswith(".") and not str(d).startswith("..")),
                    is_dotdot=str(d).startswith(".."),
                    iso_version=-1,
                )
                await iso_resource.add_folder(
                    path, None, None, folder_tags, entry.get_attributes_instances().values()
                )
            for f in files:
                path = os.path.join(root, f)
                file_tags = (ISO9660Entry, File)
                fp = BytesIO()

                facade.get_file_from_iso_fp(fp, **{path_var: path})
                file_data = fp.getvalue()

                if ";" in f:
                    f, iso_version = f.split(";")
                    iso_version = int(iso_version)
                    path = path.split(";")[0]

                    if f.endswith("."):
                        f = f[:-1]
                        path = path[:-1]
                else:
                    iso_version = -1

                entry = ISO9660Entry(
                    name=f,
                    path=path,
                    is_dir=False,
                    is_file=True,
                    is_symlink=False,
                    is_dot=(str(f).startswith(".") and not str(f).startswith("..")),
                    is_dotdot=str(f).startswith(".."),
                    iso_version=iso_version,
                )
                await iso_resource.add_file(
                    path,
                    file_data,
                    None,
                    None,
                    file_tags,
                    entry.get_attributes_instances().values(),
                )
                fp.close()

        iso.close()


MKISOFS = ComponentExternalTool(
    "mkisofs",
    "https://linux.die.net/man/8/mkisofs",
    "-help",
    apt_package="genisoimage",
    brew_package="dvdrtools",
)


class ISO9660Packer(Packer[None]):
    targets = (ISO9660Image,)
    external_dependencies = (MKISOFS,)

    async def pack(self, resource: Resource, config=None) -> None:
        iso_view = await resource.view_as(ISO9660Image)

        try:
            isolinux_bin = await resource.get_only_descendant_as_view(
                ISO9660Entry,
                r_filter=ResourceFilter(
                    attribute_filters=(
                        (ResourceAttributeValueFilter(ISO9660Entry.Name, "isolinux.bin"),)
                    ),
                ),
            )
            isolinux_bin_cmd = [
                "-b",
                isolinux_bin.path.strip("/"),
            ]  # The leading "/" is not needed in this CLI arg
        except NotFoundError:
            isolinux_bin_cmd = list()
        try:
            boot_cat = await resource.get_only_descendant_as_view(
                ISO9660Entry,
                r_filter=ResourceFilter(
                    attribute_filters=(
                        (ResourceAttributeValueFilter(ISO9660Entry.Name, "boot.cat"),)
                    ),
                ),
            )
            boot_cat_cmd = [
                "-c",
                boot_cat.path.strip("/"),
            ]  # The leading "/" is not needed in this CLI arg
        except NotFoundError:
            boot_cat_cmd = list()

        iso_attrs = resource.get_attributes(ISO9660ImageAttributes)
        temp_flush_dir = await iso_view.flush_to_disk()
        with tempfile.NamedTemporaryFile(suffix=".iso", mode="rb") as temp:
            temp.close()
            cmd = [
                "mkisofs",
                *(["-J"] if iso_attrs.has_joliet else []),
                *(["-R"] if iso_attrs.has_rockridge else []),
                *(["-V", iso_attrs.volume_identifier] if iso_attrs.volume_identifier else []),
                *(["-sysid", iso_attrs.system_identifier] if iso_attrs.system_identifier else []),
                *(["-A", iso_attrs.app_identifier] if iso_attrs.app_identifier else []),
                *(
                    [
                        "-no-emul-boot",
                        *isolinux_bin_cmd,
                        *boot_cat_cmd,
                        "-boot-info-table",
                        "-no-emul-boot",
                    ]
                    if iso_attrs.has_eltorito
                    else []
                ),
                "-allow-multidot",
                "-o",
                temp.name,
                temp_flush_dir,
            ]
            proc = await asyncio.create_subprocess_exec(*cmd)
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)
            with open(temp.name, "rb") as temp:
                new_data = temp.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicMimeIdentifier.register(ISO9660Image, "application/x-iso9660-image")
MagicDescriptionIdentifier.register(ISO9660Image, lambda s: s.startswith("ISO 9660 CD"))
