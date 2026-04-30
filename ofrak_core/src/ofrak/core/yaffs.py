import asyncio
import logging
import struct
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak_type.range import Range
from ofrak_type.endianness import Endianness

LOGGER = logging.getLogger(__name__)


class _Yaffs2UtilTool(ComponentExternalTool):
    """
    yaffs2utils binaries (mkyaffs2/unyaffs2) never exit 0 when run for help
    (they return 255 regardless), so detect installation by running with no
    arguments and checking the banner in stdout.
    """

    def __init__(self, tool: str):
        super().__init__(tool, "https://code.google.com/archive/p/yaffs2utils/", "")

    async def is_tool_installed(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tool,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
        except FileNotFoundError:
            return False
        return self.tool.encode() in stdout


MKYAFFS2 = _Yaffs2UtilTool("mkyaffs2")
UNYAFFS2 = _Yaffs2UtilTool("unyaffs2")

PAGE_SIZES = (512, 1024, 2048, 4096, 8192, 16384)
MAX_SPARE_SIZE = 512
NUM_CONFIRM_BLOCKS = 16

# Bytes at the start of the spare area, varies by endianness and ECC settings
SPARE_MAGICS = (
    b"\x00\x00\x10\x00",
    b"\x00\x10\x00\x00",
    b"\xff\xff\x00\x00\x10\x00",
    b"\xff\xff\x00\x10\x00\x00",
)

# First object is probably a dir or file with parent_id=1 and unused
# name_checksum=0xFFFF. At least, that's how Binwalk detects it.
# https://github.com/ReFirmLabs/binwalk/blob/a417b4dcf7420f9153779edf416394d0bb01cdea/src/signatures/yaffs.rs
YAFFS_HEADER_MAGICS = (
    b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff",  # LE directory
    b"\x00\x00\x00\x03\x00\x00\x00\x01\xff\xff",  # BE directory
    b"\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff",  # LE file
    b"\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff",  # BE file
)


@dataclass
class Yaffs2Filesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in YAFFS (Yet Another Flash File System) format.
    """


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Yaffs2FilesystemAttributes(ResourceAttributes):
    """
    Geometry of a YAFFS2 image.
    """

    page_size: int
    spare_size: int
    endian: Endianness


class Yaffs2Identifier(Identifier):
    """
    Identify YAFFSv2 filesystem images by checking for valid YAFFS2 object header
    magic bytes at offset 0, valid spare area magic at the detected page boundary,
    and a valid subsequent object header at the detected block size.
    """

    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config=None) -> None:
        header = await resource.get_data(range=Range(0, 10))
        if len(header) < 10 or header not in YAFFS_HEADER_MAGICS:
            return
        endian = ">" if header[0] == 0x00 else "<"

        # Upper bound: (max_page + max_spare) * max_confirm_blocks + 10
        read_size = (max(PAGE_SIZES) + MAX_SPARE_SIZE) * NUM_CONFIRM_BLOCKS + 10
        data = await resource.get_data(range=Range(0, read_size))

        page_size = detect_page_size(data)
        if page_size == 0:
            return
        spare_size = detect_spare_size(data, page_size, endian)
        if spare_size == 0:
            return

        resource.add_tag(Yaffs2Filesystem)
        resource.add_attributes(
            Yaffs2FilesystemAttributes(
                page_size=page_size,
                spare_size=spare_size,
                endian=Endianness.BIG_ENDIAN if endian == ">" else Endianness.LITTLE_ENDIAN,
            )
        )


def detect_page_size(data: bytes) -> int:
    """
    Detect page size by looking for spare magic at known page size offsets.
    """
    NUM_CHECKS = 3
    SPARE_SIZE_CANDIDATES = (16, 32, 64, 128, 256, 512)
    for page_size in PAGE_SIZES:
        for magic in SPARE_MAGICS:
            for spare_size in SPARE_SIZE_CANDIDATES:
                block_size = page_size + spare_size
                for i in range(NUM_CHECKS):
                    start = block_size * i + page_size
                    end = start + len(magic)
                    if end > len(data) or data[start:end] != magic:
                        break
                else:  # No break
                    return page_size
    return 0


def detect_spare_size(data: bytes, page_size: int, endian: str) -> int:
    """
    Detect spare size by scanning for the next valid object header after the first page.

    Searches for a valid header at each 4-byte-aligned offset in the spare region
    after the first page.  When a candidate is found, it is validated by checking
    that another valid header exists at a later block_size-aligned offset (file
    objects may have data chunks between headers).
    """
    scan_start = page_size + 4  # skip past spare magic bytes
    scan_end = min(page_size + MAX_SPARE_SIZE, len(data) - 10)
    for offset in range(scan_start, scan_end, 4):
        if parse_obj_header(data[offset:], endian):
            block_size = offset
            # Scan subsequent blocks for another valid header
            for n in range(2, NUM_CONFIRM_BLOCKS):
                later = block_size * n
                if later + 10 > len(data):
                    break
                if parse_obj_header(data[later:], endian):
                    return block_size - page_size
    return 0


def parse_obj_header(data: bytes, endian: str) -> bool:
    if len(data) < 10:
        return False
    obj_type, parent_id, name_checksum = struct.unpack_from(f"{endian}IIH", data, 0)
    return (0 <= obj_type < 6) and parent_id > 0 and name_checksum == 0xFFFF


class Yaffs2Unpacker(Unpacker[None]):
    """
    Extracts files and directories from YAFFS2 images. YAFFS2 is commonly used
    as the root filesystem in embedded Linux devices built on NAND flash,
    notably older Android devices and various industrial firmware. The unpacker
    preserves file permissions, ownership, symbolic links, and special files.
    """

    targets = (Yaffs2Filesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNYAFFS2,)

    async def unpack(self, resource: Resource, config=None):
        attrs = await _get_yaffs2_attributes(resource)
        async with resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                cmd = [
                    "unyaffs2",
                    "-p",
                    str(attrs.page_size),
                    "-s",
                    str(attrs.spare_size),
                    *endian_arg(attrs),
                    temp_path,
                    temp_flush_dir,
                ]
                proc = await asyncio.create_subprocess_exec(*cmd)
                returncode = await proc.wait()
                if proc.returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)
                view = await resource.view_as(Yaffs2Filesystem)
                await view.initialize_from_disk(temp_flush_dir)


class Yaffs2Packer(Packer[None]):
    """
    Packages files into a YAFFS2 image. The packer preserves Unix permissions,
    ownership, symbolic links, and special files, and writes the image using the
    same page size, spare size, and endianness detected at unpack time.
    """

    targets = (Yaffs2Filesystem,)
    external_dependencies = (MKYAFFS2,)

    async def pack(self, resource: Resource, config=None):
        attrs = await _get_yaffs2_attributes(resource)
        view: Yaffs2Filesystem = await resource.view_as(Yaffs2Filesystem)
        temp_flush_dir = await view.flush_to_disk()
        with tempfile.NamedTemporaryFile(
            suffix=".yaffs2", mode="rb", delete_on_close=False
        ) as temp:
            temp.close()
            cmd = [
                "mkyaffs2",
                "-p",
                str(attrs.page_size),
                "-s",
                str(attrs.spare_size),
                *endian_arg(attrs),
                temp_flush_dir,
                temp.name,
            ]
            proc = await asyncio.create_subprocess_exec(*cmd)
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)
            with open(temp.name, "rb") as new_fh:
                new_data = new_fh.read()
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


async def _get_yaffs2_attributes(resource: Resource) -> Yaffs2FilesystemAttributes:
    if resource.has_attributes(Yaffs2FilesystemAttributes):
        return resource.get_attributes(Yaffs2FilesystemAttributes)
    return Yaffs2FilesystemAttributes(
        page_size=2048,
        spare_size=64,
        endian=Endianness.LITTLE_ENDIAN,
    )


def endian_arg(attrs: Yaffs2FilesystemAttributes) -> list:
    # mkyaffs2/unyaffs2 use -e to swap from the host (little-endian) byte order.
    return ["-e"] if attrs.endian == Endianness.BIG_ENDIAN else []
