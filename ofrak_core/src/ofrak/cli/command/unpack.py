import os.path
from typing import Optional

from ofrak import OFRAKContext, Resource

import argparse
from pathlib import Path
import time
import sys

from ofrak.cli.ofrak_cli import OfrakCommandRunsScript
from ofrak.core import FilesystemEntry
from ofrak.gui.server import open_gui


class UnpackCommand(OfrakCommandRunsScript):
    def __init__(self):
        self._filename_trackers = dict()
        self._resource_paths = dict()

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
            "--recursive",
            "-r",
            action="store_true",
            default=False,
            help="Unpack recursively: all resources unpacked from the root will be unpack, as "
            "well as all resources unpacked from those, and so.",
        )
        subparser.add_argument("filename", help="File to unpack")

        # GUI args
        subparser.add_argument(
            "--gui",
            action="store_true",
            help="Open the OFRAK GUI after unpacking",
            default=False,
        )
        subparser.add_argument(
            "-gH",
            "--gui-hostname",
            action="store",
            help="Set GUI server host address.",
            default="127.0.0.1",
        )
        subparser.add_argument(
            "-gp",
            "--gui-port",
            action="store",
            type=int,
            help="Set GUI server host port.",
            default=8080,
        )
        subparser.add_argument(
            "--gui-no-browser",
            action="store_true",
            help="Don't open the browser to the OFRAK GUI",
        )

        self.add_ofrak_arguments(subparser)

        return subparser

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: argparse.Namespace):
        print(f"Unpacking file: {args.filename}\n")
        root_resource = await ofrak_context.create_root_resource_from_file(args.filename)

        if args.recursive:
            await root_resource.unpack_recursively()
        else:
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
            await self.get_filesystem_name(root_resource),
        )
        info_dump_path = os.path.join(extraction_dir, "__ofrak_info__")
        await self.resource_tree_to_files(root_resource, root_resource_path)

        info_dump = await root_resource.summarize_tree(
            summarize_resource_callback=lambda resource: _custom_summarize_resource(resource, self)
        )
        # Some characters in filename bytestrings are no valid unicode, can't be printed, must be replaced
        # https://stackoverflow.com/questions/27366479/python-3-os-walk-file-paths-unicodeencodeerror-utf-8-codec-cant-encode-s
        info_dump = info_dump.encode("utf-8", "replace").decode(
            "utf-8",
        )

        with open(info_dump_path, "w", encoding="utf-8") as f:
            f.write(info_dump)

        print(info_dump)

        if args.gui:
            server = await open_gui(
                args.gui_hostname,
                args.gui_port,
                focus_resource=root_resource,
                open_in_browser=(not args.gui_no_browser),
            )
            await server.run_until_cancelled()

    async def resource_tree_to_files(self, resource: Resource, path):
        children_dir = path + ".ofrak_children"
        for child_resource in await resource.get_children():
            filename = await self.get_filesystem_name(child_resource)

            if not os.path.exists(children_dir):
                os.mkdir(children_dir)

            child_path = os.path.join(children_dir, filename)
            await self.resource_tree_to_files(child_resource, child_path)

        if resource.get_data_id() is None:
            return
        data = await resource.get_data()
        if len(data) == 0:
            return
        with open(path, "wb") as f:
            f.write(data)
        self._resource_paths[resource.get_id()] = path

    async def get_filesystem_name(self, resource: Resource) -> str:
        if resource.has_tag(FilesystemEntry):
            file_view = await resource.view_as(FilesystemEntry)
            filename = file_view.name
        else:
            filename = resource.get_caption()

        parent_id = resource.get_model().parent_id
        filesystem_name_key = (parent_id, filename)
        if filesystem_name_key in self._filename_trackers:
            name_suffixes = self._filename_trackers[filesystem_name_key]
        else:
            name_suffixes = {resource.get_id(): ""}
            self._filename_trackers[filesystem_name_key] = name_suffixes

            return filename

        if resource.get_id() in name_suffixes:
            return filename + name_suffixes[resource.get_id()]
        else:
            suffix = f"_{len(name_suffixes)}"
            name_suffixes[resource.get_id()] = suffix
            return filename + suffix

    def get_path(self, resource: Resource) -> Optional[str]:
        return self._resource_paths.get(resource.get_id())


async def _custom_summarize_resource(resource: Resource, unpack_cmd: UnpackCommand) -> str:
    attributes_info = ", ".join(attrs_type.__name__ for attrs_type in resource._resource.attributes)
    name = await unpack_cmd.get_filesystem_name(resource)
    if " " in name:
        name = f"'{name}'"

    if resource._resource.data_id:
        data_info = f", size={await resource.get_data_length()} bytes"
    else:
        data_info = ", no data"

    path = unpack_cmd.get_path(resource)
    if path is None:
        path_info = ", (not written)"
    else:
        path_info = f", extracted-path={unpack_cmd.get_path(resource)}"
    return f"{name}: [attributes=({attributes_info}){data_info}{path_info}]"
