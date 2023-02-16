import logging
import os
from dataclasses import dataclass
from io import BytesIO
from typing import Iterable, Optional

from pycdlib import PyCdlib

from ofrak.component.analyzer import Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, File, Folder
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.resource_model import index
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter
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


class ISO9660Packer(Packer[None]):
    """
    Pack files in an ISO 9660 image.
    """

    id = b"ISO9660Packer"
    targets = (ISO9660Image,)

    async def pack(self, resource: Resource, config=None):
        image_attributes = resource.get_attributes(ISO9660ImageAttributes)

        iso_result = PyCdlib()
        iso_result.new(
            interchange_level=image_attributes.interchange_level,
            sys_ident=image_attributes.system_identifier,
            vol_ident=image_attributes.volume_identifier,
            app_ident_str=image_attributes.app_identifier,
            joliet=image_attributes.joliet_level,
            rock_ridge=image_attributes.rockridge_version,
            xa=image_attributes.extended_attributes,
            udf=image_attributes.udf_version,
        )

        if image_attributes.has_joliet:
            resource.add_tag(JolietISO9660Image)
            facade = iso_result.get_joliet_facade()
            path_arg = "joliet_path"
        elif image_attributes.has_udf:
            resource.add_tag(UdfISO9660Image)
            facade = iso_result.get_udf_facade()
            path_arg = "udf_path"
            LOGGER.warning("UDF images are not currently supported")
        elif image_attributes.has_rockridge:
            LOGGER.warning("Rock Ridge images are not currently supported")
            resource.add_tag(RockRidgeISO9660Image)
            facade = iso_result.get_rock_ridge_facade()
            path_arg = "rr_name"
        else:
            facade = iso_result.get_iso9660_facade()
            path_arg = "iso_path"

        if image_attributes.has_eltorito:
            LOGGER.warning("El Torito images are not currently supported")

        child_queue = [
            d
            for d in await resource.get_children_as_view(
                ISO9660Entry, r_filter=ResourceFilter(tags=(ISO9660Entry,))
            )
        ]

        while len(child_queue) > 0:
            child = child_queue.pop(0)

            path = child.path
            if child.iso_version != -1:
                path += ";" + str(child.iso_version)

            if child.resource.has_tag(Folder):
                facade.add_directory(**{path_arg: path})
                for d in await child.resource.get_children_as_view(
                    ISO9660Entry, r_filter=ResourceFilter(tags=(ISO9660Entry,))
                ):
                    child_queue.append(d)
            elif child.resource.has_tag(File):
                file_data = await child.resource.get_data()
                facade.add_fp(BytesIO(file_data), len(file_data), **{path_arg: path})

        result = BytesIO()
        iso_result.write_fp(result)
        iso_result.close()

        iso_data = result.getvalue()
        result.close()
        resource.queue_patch(Range(0, await resource.get_data_length()), iso_data)


MagicMimeIdentifier.register(ISO9660Image, "application/x-iso9660-image")
MagicDescriptionIdentifier.register(ISO9660Image, lambda s: s.startswith("ISO 9660 CD"))
