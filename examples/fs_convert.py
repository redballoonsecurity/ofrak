"""
Convert between filesystem archive formats using OFRAK.
"""
import argparse
import os
import sys

from ofrak import OFRAK, OFRAKContext
from ofrak.core.cpio import CpioArchiveType, CpioFilesystem
from ofrak.core.cramfs import Cramfs
from ofrak.core.iso9660 import ISO9660Image
from ofrak.core.jffs2 import Jffs2Filesystem
from ofrak.core.seven_zip import SevenZFilesystem
from ofrak.core.squashfs import SquashfsFilesystem
from ofrak.core.tar import TarArchive
from ofrak.core.ubifs import Ubifs
from ofrak.core.zip import ZipArchive

FORMATS = {
    "zip": ZipArchive,
    "tar": TarArchive,
    "cpio": CpioFilesystem,
    "squashfs": SquashfsFilesystem,
    "cramfs": Cramfs,
    "iso9660": ISO9660Image,
    "jffs2": Jffs2Filesystem,
    "7z": SevenZFilesystem,
    "ubifs": Ubifs,
}

EXTENSION_MAP = {
    ".zip": "zip",
    ".tar": "tar",
    ".cpio": "cpio",
    ".sqsh": "squashfs",
    ".squashfs": "squashfs",
    ".cramfs": "cramfs",
    ".iso": "iso9660",
    ".jffs2": "jffs2",
    ".7z": "7z",
    ".ubifs": "ubifs",
}

# Default views for formats that require attributes beyond just a tag.
FORMAT_DEFAULT_VIEWS = {
    "cpio": CpioFilesystem(CpioArchiveType.NEW_ASCII),
}


def detect_format_from_extension(path: str) -> str:  # pragma: no cover
    ext = os.path.splitext(path)[1].lower()
    fmt = EXTENSION_MAP.get(ext)
    if fmt is None:
        sys.exit(
            f"Cannot detect format from extension '{ext}'. "
            f"Use --to with one of: {', '.join(FORMATS.keys())}"
        )
    return fmt


async def convert_filesystem(
    ofrak_context: OFRAKContext,
    input_path: str,
    output_path: str,
    target_format: str,
) -> None:
    root = await ofrak_context.create_root_resource_from_file(input_path)
    await root.unpack()

    for fmt_tag in FORMATS.values():
        root.remove_tag(fmt_tag)

    default_view = FORMAT_DEFAULT_VIEWS.get(target_format)
    if default_view is not None:
        root.add_view(default_view)
    else:
        target_tag = FORMATS[target_format]
        root.add_tag(target_tag)

    await root.save()
    await root.pack()
    await root.flush_data_to_disk(output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert between filesystem formats using OFRAK")
    parser.add_argument("-i", "--input", required=True, help="Input filesystem file")
    parser.add_argument("-o", "--output", required=True, help="Output filesystem file")
    parser.add_argument(
        "--to",
        choices=FORMATS.keys(),
        default=None,
        help="Target format (auto-detected from output extension if omitted)",
    )
    args = parser.parse_args()

    target_format = args.to if args.to else detect_format_from_extension(args.output)

    ofrak = OFRAK()
    ofrak.run(convert_filesystem, args.input, args.output, target_format)
