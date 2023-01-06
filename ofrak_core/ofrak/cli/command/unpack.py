from ofrak import OFRAKContext

import argparse
from pathlib import Path
import time
import sys

from ofrak.cli.ofrak_cli import OfrakCommandRunsScript


class Unpack(OfrakCommandRunsScript):
    def create_parser(self, parser: argparse._SubParsersAction):
        subparser = parser.add_parser(
            "unpack",
            help="Unpack all identified structures that can be unpacked with OFRAK",
            description="Import a file as an OFRAK resource, then identifies and unpacks it. The "
            "resource's children are written to the output directory as individual "
            "files. Children which have no data are not written as files.",
        )
        subparser.add_argument(
            "-o",
            "--output_directory",
            help="Directory to write unpacked resource tree to. If no directory is given, a new one"
            " will be created in the same directory as the file being unpacked.",
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

        for child_resource in await root_resource.get_children():
            # TODO: make stable, sensible filename
            filename = child_resource.get_id().hex()
            outpath = str(extraction_dir / filename)

            try:
                await child_resource.flush_to_disk(outpath)
            except Exception as e:
                print(f"Could not unpack {filename} with error: {e}")
