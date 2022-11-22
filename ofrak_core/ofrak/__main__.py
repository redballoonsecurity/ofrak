from argparse import ArgumentParser
from inspect import isabstract
from itertools import chain
from types import ModuleType
from typing import Dict, List, Iterable

from ofrak import OFRAK
from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import ComponentExternalTool
from synthol.injector import DependencyInjector

"""
ofrak list --missing-dependencies --packages
ofrak deps --missing-only --check --packages-only
"""


_OFRAK_PACKAGES = None
_OFRAK_COMPONENTS = None
_OFRAK_DEPENDENCIES = None


def _get_all_ofrak_packages() -> List[ModuleType]:
    global _OFRAK_PACKAGES
    if not _OFRAK_PACKAGES:
        o = OFRAK()
        _OFRAK_PACKAGES = list(o.get_installed_ofrak_packages())
    return _OFRAK_PACKAGES


def _get_ofrak_components() -> Dict[ModuleType, List[ComponentInterface]]:
    global _OFRAK_COMPONENTS
    if not _OFRAK_COMPONENTS:
        ofrak_packages = _get_all_ofrak_packages()
        _OFRAK_COMPONENTS = {}
        prev_packages = []
        next_packages = list(ofrak_packages)
        while next_packages:
            package = next_packages.pop(0)
            other_packages = prev_packages + next_packages
            injector = DependencyInjector()
            # Make sure that if a package has imports from another package, injector does not
            # follow this reference and discover code from the other package
            injector.discover(package, blacklisted_modules=other_packages)
            prev_packages.append(package)

            _OFRAK_COMPONENTS[package] = [
                provider._factory
                for provider in injector._providers[ComponentInterface]
                if not isabstract(provider._factory)
            ]
    return _OFRAK_COMPONENTS


def _get_ofrak_dependencies() -> Dict[ComponentInterface, List[ComponentExternalTool]]:
    global _OFRAK_DEPENDENCIES
    if not _OFRAK_DEPENDENCIES:
        ofrak_components = chain(*(_get_ofrak_components().values()))
        _OFRAK_DEPENDENCIES = {c: list(c.external_dependencies) for c in ofrak_components}
    return _OFRAK_DEPENDENCIES


def setup_list_argparser(ofrak_subparsers):
    list_parser = ofrak_subparsers.add_parser("list")
    list_parser.add_argument(
        "--packages", "-p", action="store_true", help="List installed OFRAK packages"
    )
    list_parser.add_argument(
        "--components", "-c", action="store_true", help="List installed OFRAK components"
    )
    list_parser.add_argument(
        "--dependencies", "-d", action="store_true", help="List dependencies of OFRAK components"
    )

    def ofrak_list_handler(args):
        output_struct = dict()

        output_lines = []

        indent = 0
        for mod in _get_all_ofrak_packages():
            if args.packages:
                output_lines.append("\t" * indent + mod.__name__)
                indent += 1
            for component in _get_ofrak_components()[mod]:
                if args.components:
                    output_lines.append("\t" * indent + component.__name__)
                    indent += 1
                for dep in _get_ofrak_dependencies()[component]:
                    if args.dependencies:
                        output_lines.append("\t" * indent + dep.tool)
                if args.components:
                    indent -= 1
            if args.packages:
                indent -= 1

        _print_lines_without_duplicates(output_lines)

    list_parser.set_defaults(func=ofrak_list_handler)


def setup_deps_argparser(ofrak_subparsers):
    deps_parser = ofrak_subparsers.add_parser("deps")

    deps_parser.add_argument(
        "--missing-only",
        action="store_true",
        help="Only output information for missing dependencies (will check all dependencies)",
    )

    deps_parser.add_argument(
        "--dependency-packages",
        action="store",
        dest="package_manager",
        choices=("apt", "brew"),
        help="List names of packages (known to <package_manager>) which provide dependencies "
        "required by installed OFRAK packages.",
        default=None,
    )
    deps_parser.add_argument(
        "--check", "-c", action="store_true", help="Check that each dependency is present"
    )

    def ofrak_deps_handler(args):
        deps_by_component = _get_ofrak_dependencies()
        dependencies = list()

        for dep_list in deps_by_component.values():
            for dep in dep_list:
                if args.check or args.missing_only:
                    installed_correctly = dep.is_tool_installed()
                else:
                    installed_correctly = None

                if args.missing_only and installed_correctly is True:
                    continue
                else:
                    dependencies.append((dep, installed_correctly))

        output_lines = []

        for dep, is_installed in dependencies:
            if args.check:
                output_lines.append(
                    f"{dep.tool}{' (Missing)' if not is_installed else ' (Installed)'}"
                )
            elif args.package_manager:
                if args.package_manager == "apt":
                    dep_pkg = dep.apt_package
                elif args.package_manager == "brew":
                    dep_pkg = dep.brew_package
                else:
                    dep_pkg = None
                if dep_pkg:
                    output_lines.append(dep_pkg)

        _print_lines_without_duplicates(output_lines)

    deps_parser.set_defaults(func=ofrak_deps_handler)


def setup_argparser():
    ofrak_parser = ArgumentParser()

    ofrak_subparsers = ofrak_parser.add_subparsers(
        help="Command line utilities to use or configure OFRAK"
    )

    setup_list_argparser(ofrak_subparsers)
    setup_deps_argparser(ofrak_subparsers)

    return ofrak_parser


def _print_lines_without_duplicates(output_lines: Iterable[str]):
    # strip duplicates
    prev_indent = 0
    seen = set()
    deduplicated_lines = []
    for line in output_lines:
        indent = line.rfind("\t") + 1
        if indent != prev_indent:
            seen = set()
        prev_indent = indent
        if line not in seen:
            deduplicated_lines.append(line)
        seen.add(line)

    for line in deduplicated_lines:
        print(line)


if __name__ == "__main__":
    parser = setup_argparser()
    args = parser.parse_args()
    args.func(args)
