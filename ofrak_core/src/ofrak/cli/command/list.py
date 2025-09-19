from argparse import Namespace
from typing import Iterable, Set

from ofrak.cli.ofrak_cli import OfrakCommand, OFRAKEnvironment


class ListCommand(OfrakCommand):
    def create_parser(self, ofrak_subparsers):
        list_parser = ofrak_subparsers.add_parser(
            "list",
            help="List installed OFRAK modules and/or components.",
            description="List installed OFRAK modules and/or components. By default, prints all "
            "installed components, organized by module (equivalent to `--packages --components` "
            "flags)",
        )
        list_parser.add_argument(
            "--packages",
            "-p",
            action="store_true",
            help="List installed OFRAK packages",
        )
        list_parser.add_argument(
            "--components",
            "-c",
            action="store_true",
            help="List installed OFRAK components",
        )
        return list_parser

    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):
        output_lines = []

        if args.components or args.packages:
            list_components = args.components
            list_packages = args.packages
        else:
            list_components = True
            list_packages = True

        indent = 0
        for mod in ofrak_env.packages.values():
            if list_packages:
                output_lines.append("\t" * indent + mod.__name__)
                indent += 1
            for component in ofrak_env.components_by_package[mod]:
                if list_components:
                    output_lines.append("\t" * indent + component.__name__)
            if list_packages:
                indent -= 1

        _print_lines_without_duplicates(output_lines)


def _print_lines_without_duplicates(output_lines: Iterable[str]):
    # strip duplicates, resetting the memory of duplicates when indentation changes
    prev_indent = 0
    seen: Set[str] = set()
    for line in output_lines:
        indent = line.rfind("\t") + 1
        if indent != prev_indent:
            seen = set()
        prev_indent = indent
        if line not in seen:
            print(line)
        seen.add(line)
