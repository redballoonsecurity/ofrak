from argparse import ArgumentParser
from inspect import isabstract
from itertools import chain
from types import ModuleType
from typing import Dict, List, Iterable, Optional, Type, Set

from ofrak import OFRAK
from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import ComponentExternalTool
from ofrak_type.error import NotFoundError
from synthol.injector import DependencyInjector

"""
ofrak list --missing-dependencies --packages
ofrak deps --missing-only --check --packages-only
"""


_OFRAK_PACKAGES: Optional[List[ModuleType]] = None
_OFRAK_COMPONENTS: Optional[Dict[ModuleType, List[Type[ComponentInterface]]]] = None
_OFRAK_DEPENDENCIES: Optional[Dict[Type[ComponentInterface], List[ComponentExternalTool]]] = None

_OFRAK_PACKAGES_BY_NAME: Optional[Dict[str, ModuleType]] = None
_OFRAK_COMPONENTS_BY_NAME: Optional[Dict[str, Type[ComponentInterface]]] = None


def _get_all_ofrak_packages() -> List[ModuleType]:
    global _OFRAK_PACKAGES
    if not _OFRAK_PACKAGES:
        o = OFRAK()
        _OFRAK_PACKAGES = list(o.get_installed_ofrak_packages())
    return _OFRAK_PACKAGES


def _get_package_by_name(pkg_name: str) -> ModuleType:
    global _OFRAK_PACKAGES_BY_NAME
    if _OFRAK_PACKAGES_BY_NAME is None:
        _OFRAK_PACKAGES_BY_NAME = {pkg.__name__: pkg for pkg in _get_all_ofrak_packages()}
    pkg = _OFRAK_PACKAGES_BY_NAME.get(pkg_name)
    if not pkg:
        raise NotFoundError(f"No OFRAK package with the name {pkg_name}")
    else:
        return pkg


def _get_ofrak_components() -> Dict[ModuleType, List[Type[ComponentInterface]]]:
    global _OFRAK_COMPONENTS
    if not _OFRAK_COMPONENTS:
        ofrak_packages = _get_all_ofrak_packages()
        _OFRAK_COMPONENTS = {}
        prev_packages: List[ModuleType] = []
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


def _get_component_by_name(component_name: str) -> Type[ComponentInterface]:
    global _OFRAK_COMPONENTS_BY_NAME
    if _OFRAK_COMPONENTS_BY_NAME is None:
        _OFRAK_COMPONENTS_BY_NAME = {c.__name__: c for c in _get_ofrak_dependencies().keys()}
    component = _OFRAK_COMPONENTS_BY_NAME.get(component_name)
    if not component:
        raise NotFoundError(f"No OFRAK component with the name {component_name}")
    else:
        return component


def _get_ofrak_dependencies() -> Dict[Type[ComponentInterface], List[ComponentExternalTool]]:
    global _OFRAK_DEPENDENCIES
    if not _OFRAK_DEPENDENCIES:
        ofrak_components = chain(*(_get_ofrak_components().values()))
        _OFRAK_DEPENDENCIES = {c: list(c.external_dependencies) for c in ofrak_components}  # type: ignore
    return _OFRAK_DEPENDENCIES


def setup_list_argparser(ofrak_subparsers):
    list_parser = ofrak_subparsers.add_parser(
        "list",
        help="List installed OFRAK modules and/or components. By default, prints all "
        "installed components, organized by module (equivalent to `--packages --components` "
        "flags)",
    )
    list_parser.add_argument(
        "--packages", "-p", action="store_true", help="List installed OFRAK packages", default=True
    )
    list_parser.add_argument(
        "--components",
        "-c",
        action="store_true",
        help="List installed OFRAK components",
        default=True,
    )

    def ofrak_list_handler(args):
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
                if args.components:
                    indent -= 1
            if args.packages:
                indent -= 1

        _print_lines_without_duplicates(output_lines)

    list_parser.set_defaults(func=ofrak_list_handler)


def setup_deps_argparser(ofrak_subparsers):
    deps_parser = ofrak_subparsers.add_parser(
        "deps",
        help="Show/check the dependencies of OFRAK components. Can show the brew/apt install "
        "packages for dependencies, and filter by component or package (if no "
        "component/package filters are provided, all dependencies are included).",
    )

    deps_parser.add_argument(
        "--package", action="append", help="Include dependencies of this package"
    )
    deps_parser.add_argument(
        "--component", action="append", help="Include dependencies of this component"
    )
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
        dependencies = list()

        if args.package:
            packages = [_get_package_by_name(pkg_name) for pkg_name in args.package]
        elif args.component:
            packages = []
        else:
            packages = _get_all_ofrak_packages()

        if args.component:
            components = [
                _get_component_by_name(component_name) for component_name in args.component
            ]
        elif args.package:
            components = []
        else:
            components = list(_get_ofrak_dependencies().keys())

        components_by_pkg = _get_ofrak_components()
        for pkg in packages:
            components.extend(components_by_pkg[pkg])

        if not components:
            return

        deps_by_component = _get_ofrak_dependencies()
        components_by_dep = dict()
        for component in components:
            dep_list = deps_by_component[component]
            for dep in dep_list:
                if args.check or args.missing_only:
                    installed_correctly = dep.is_tool_installed()
                else:
                    installed_correctly = None

                if args.missing_only and installed_correctly is True:
                    continue

                dependencies.append((dep, installed_correctly))
                if dep not in components_by_dep:
                    components_by_dep[dep] = set()
                components_by_dep[dep].add(component.__name__)

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
            else:
                output_lines.append(f"{dep.tool} [{', '.join(c for c in components_by_dep[dep])}]")

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
    seen: Set[str] = set()
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
