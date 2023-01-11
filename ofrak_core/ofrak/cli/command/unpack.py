import os.path
from typing import Dict

from ofrak import OFRAKContext, Resource

import argparse
from pathlib import Path
import time
import sys

from ofrak.cli.command.identify import Identify
from ofrak.cli.ofrak_cli import OfrakCommandRunsScript
from ofrak.core import FilesystemEntry


class Unpack(OfrakCommandRunsScript):
    def create_parser(self, parser: argparse._SubParsersAction):
        subparser = parser.add_parser(
            "unpack",
            help="Unpack all identified structures that can be unpacked with OFRAK",
            description="Import a file as an OFRAK resource, then identifies and unpacks it. The "
            "resource's children are written to the output directory as individual "
            "files. Children which have no data are not written as files. A file `__ofrak_info__` "
            "is also written to the output directory, containing the known OFRAK tags and "
            "attributes for each descendant.",
        )
        subparser.add_argument(
            "-o",
            "--output_directory",
            help="Directory to write unpacked resource tree to. If no directory is given, a new one"
            " will be created in the same directory as the file being unpacked.",
        )
        subparser.add_argument(
            "--print-info",
            "-p",
            help="Print contents of __ofrak_info__ (which may be large!) to stdout as well as the "
            "__ofrak_info__ file.",
            action="store_true",
        )
        subparser.add_argument("filename", help="File to unpack")
        self.add_ofrak_arguments(subparser)

        return subparser

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: argparse.Namespace):
        print(f"Unpacking file: {args.filename}\n")
        root_resource = await ofrak_context.create_root_resource_from_file(args.filename)

        await root_resource.unpack()

        if args.output_directory:
            extraction_dir = Path(args.output_directory)
        else:
            file_path = Path(args.filename)
            parent_dir = file_path.parent
            extraction_dir = Path(
                parent_dir / f'{file_path.name}_extracted_{time.strftime("%Y%m%d%H%M%S")}'
            )

        if extraction_dir.exists():
            if any(extraction_dir.iterdir()):
                print(f"Found files in {extraction_dir}, ABORTING!", file=sys.stderr)
                return
        else:
            extraction_dir.mkdir()

        print(f"Extracting data to {extraction_dir}")

        root_resource_path = os.path.join(
            extraction_dir,
            await self._get_filesystem_name(root_resource),
        )
        info_dump_path = os.path.join(extraction_dir, "__ofrak_info__")
        info_dump = await self.resource_tree_to_files(root_resource, root_resource_path)

        with open(info_dump_path, "wb") as f:
            f.write(info_dump.encode("utf-8", "surrogateescape"))

        if args.print_info:
            print(info_dump)

    async def resource_tree_to_files(self, resource: Resource, path) -> str:
        info_dump = path + "\n" + await Identify.print_info(resource)

        name_counters: Dict[str, int] = dict()
        children_dir = path + ".ofrak_children"
        for child_resource in await resource.get_children():
            filename = await self._get_filesystem_name(child_resource)
            if filename in name_counters:
                name_counters[filename] += 1
                filename = filename + f"_{name_counters[filename]}"
            else:
                name_counters[filename] = 0

            if not os.path.exists(children_dir):
                os.mkdir(children_dir)

            child_path = os.path.join(children_dir, filename)
            child_info_dump = await self.resource_tree_to_files(child_resource, child_path)
            info_dump = info_dump + "\n\n" + child_info_dump

        if resource.get_data_id() is None:
            return info_dump
        data = await resource.get_data()
        if len(data) == 0:
            return info_dump
        with open(path, "wb") as f:
            f.write(data)

        return info_dump

    async def _get_filesystem_name(self, resource: Resource) -> str:
        if resource.has_tag(FilesystemEntry):
            file_view = await resource.view_as(FilesystemEntry)
            filename = file_view.name
        else:
            filename = resource.get_caption()
        return filename
