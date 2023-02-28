import asyncio
from argparse import RawDescriptionHelpFormatter, Namespace
from types import ModuleType
from typing import Iterable, Set, Dict

from ofrak.cli.ofrak_cli import OfrakCommand, OFRAKEnvironment
from ofrak.model.component_model import ComponentExternalTool


class DepsCommand(OfrakCommand):
    def create_parser(self, ofrak_subparsers):
        deps_parser = ofrak_subparsers.add_parser(
            "deps",
            help="Show and check the external (non-Python) dependencies of OFRAK components. Can "
            "show the brew/apt install packages for dependencies, and filter by component or "
            "package.",
            description="Show/check the dependencies of OFRAK components.\n"
            "Examples:\n"
            "\tGet all dependencies of core ofrak:\n"
            "\t\tpython3 -m ofrak deps --package ofrak\n"
            "\tList all the apt packages needed for missing dependencies:\n"
            "\t\tpython3 -m ofrak deps --missing-only --packages-for apt",
            formatter_class=RawDescriptionHelpFormatter,
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
            help="Only output information for missing dependencies",
        )
        mutex_group = deps_parser.add_mutually_exclusive_group()
        mutex_group.add_argument(
            "--packages-for",
            action="store",
            choices=("apt", "brew"),
            help="List only names of packages (known to the selected package manager) which "
            "provide required dependencies.",
            default=None,
        )
        mutex_group.add_argument(
            "--no-packages-for",
            action="store",
            choices=("apt", "brew"),
            help="List only dependencies which cannot be installed via the selected package "
            "manager.",
            default=None,
        )
        deps_parser.add_argument(
            "--no-check",
            "-n",
            action="store_true",
            help="Do not check that each dependency is present (ignored if --missing-only is also "
            "provided)",
        )
        return deps_parser

    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):
        dependencies = set()
        packages: Iterable[ModuleType]
        check_deps = args.missing_only or not args.no_check

        if args.package or args.component:
            packages = []
        else:
            packages = ofrak_env.packages.values()

        if args.package:
            packages = [ofrak_env.packages[pkg_name] for pkg_name in args.package]

        if args.component:
            components = [ofrak_env.components[component_name] for component_name in args.component]
        else:
            components = []

        for pkg in packages:
            components.extend(ofrak_env.components_by_package[pkg])

        if not components:
            return
        components_by_dep: Dict[ComponentExternalTool, Set[str]] = dict()
        for component in ofrak_env.components.values():
            for dep in component.external_dependencies:  # type: ignore
                if dep not in components_by_dep:
                    components_by_dep[dep] = set()
                components_by_dep[dep].add(component.__name__)

        for component in components:
            dep_list = ofrak_env.dependencies_by_component[component]
            for dep in dep_list:
                dependencies.add(dep)

        for dep in dependencies:
            if check_deps:
                is_installed = asyncio.run(dep.is_tool_installed())
            else:
                is_installed = None

            if args.missing_only and is_installed:
                continue

            if args.no_packages_for:
                pkg_manager = args.no_packages_for
            elif args.packages_for:
                pkg_manager = args.packages_for
            else:
                pkg_manager = None

            if pkg_manager == "apt":
                dep_pkg = dep.apt_package
            elif pkg_manager == "brew":
                dep_pkg = dep.brew_package
            else:
                dep_pkg = None

            if args.packages_for:
                if dep_pkg is not None:
                    print(dep_pkg)
                continue
            elif args.no_packages_for and dep_pkg is not None:
                continue

            dependency_info = f"{dep.tool}\n\t{dep.tool_homepage}\n\t[{', '.join(c for c in components_by_dep[dep])}]"
            if not args.no_check:
                dependency_info = f"[{' ' if not is_installed else '✓'}] " + dependency_info

            print(dependency_info)
