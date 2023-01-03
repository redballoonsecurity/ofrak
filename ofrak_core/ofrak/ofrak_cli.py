import functools
import sys
from abc import ABC, abstractmethod
from argparse import Namespace, ArgumentParser, RawDescriptionHelpFormatter
from inspect import isabstract
from types import ModuleType
from typing import Dict, Optional, Type, List, Iterable, Set, Sequence

from importlib_metadata import entry_points

from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import ComponentExternalTool
from synthol.injector import DependencyInjector


class OFRAKEnvironment:
    def __init__(self):
        self._ofrak_packages: Optional[Dict[str, ModuleType]] = None
        self._ofrak_components: Optional[Dict[str, Type[ComponentInterface]]] = None
        self._ofrak_package_components: Optional[
            Dict[ModuleType, List[Type[ComponentInterface]]]
        ] = None
        self._ofrak_component_dependencies: Optional[
            Dict[Type[ComponentInterface], List[ComponentExternalTool]]
        ] = None

        _OFRAK_PACKAGES: Optional[List[ModuleType]] = None
        _OFRAK_COMPONENTS: Optional[Dict[ModuleType, List[Type[ComponentInterface]]]] = None
        _OFRAK_DEPENDENCIES: Optional[
            Dict[Type[ComponentInterface], List[ComponentExternalTool]]
        ] = None

        _OFRAK_PACKAGES_BY_NAME: Optional[Dict[str, ModuleType]] = None
        _OFRAK_COMPONENTS_BY_NAME: Optional[Dict[str, Type[ComponentInterface]]] = None

    @property
    def packages(self) -> Dict[str, ModuleType]:
        if self._ofrak_packages is None:
            ofrak_eps = entry_points(group="ofrak.packages")
            import ofrak

            installed_ofrak_pkgs = [ofrak] + [ofrak_pkg.load() for ofrak_pkg in ofrak_eps]
            self._ofrak_packages = {pkg.__name__: pkg for pkg in installed_ofrak_pkgs}
        return self._ofrak_packages

    @property
    def components(self) -> Dict[str, Type[ComponentInterface]]:
        if self._ofrak_components is None:
            self._ofrak_components = {}
            for components in self.components_by_package.values():
                for component in components:
                    self._ofrak_components[component.__name__] = component

        return self._ofrak_components

    @property
    def components_by_package(self) -> Dict[ModuleType, List[Type[ComponentInterface]]]:
        if self._ofrak_package_components is None:
            self._ofrak_package_components = {}
            prev_packages: List[ModuleType] = []
            next_packages = list(self.packages.values())
            while next_packages:
                package = next_packages.pop(0)
                other_packages = prev_packages + next_packages
                injector = DependencyInjector()
                # Make sure that if a package has imports from another package, injector does not
                # follow this reference and discover code from the other package
                injector.discover(package, blacklisted_modules=other_packages)
                prev_packages.append(package)

                self._ofrak_package_components[package] = []

                for provider in injector._providers[ComponentInterface]:
                    if isabstract(provider._factory):
                        continue
                    component_type = provider._factory
                    self._ofrak_package_components[package].append(component_type)

        return self._ofrak_package_components

    @property
    def dependencies_by_component(
        self,
    ) -> Dict[Type[ComponentInterface], List[ComponentExternalTool]]:
        if self._ofrak_component_dependencies is None:
            ofrak_components = self.components.values()
            self._ofrak_component_dependencies = {
                c: list(c.external_dependencies) for c in ofrak_components  # type: ignore
            }
        return self._ofrak_component_dependencies


class OFRAKSubCommand(ABC):
    @abstractmethod
    def create_parser(self, ofrak_subparsers):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def handler(ofrak_env: OFRAKEnvironment, args: Namespace):
        raise NotImplementedError()


class ListSubCommand(OFRAKSubCommand):
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

    @staticmethod
    def handler(ofrak_env: OFRAKEnvironment, args: Namespace):
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


class DepsSubCommand(OFRAKSubCommand):
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

    @staticmethod
    def handler(ofrak_env: OFRAKEnvironment, args: Namespace):
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
                is_installed = dep.is_tool_installed()
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


class OFRAKCommandLineInterface:
    def __init__(
        self,
        ofrak_env: OFRAKEnvironment = OFRAKEnvironment(),
        subcommands: Iterable[OFRAKSubCommand] = (ListSubCommand(), DepsSubCommand()),
    ):
        self.ofrak_parser = ArgumentParser()
        ofrak_subparsers = self.ofrak_parser.add_subparsers(
            help="Command line utilities to use or configure OFRAK"
        )

        for ofrak_subcommand in subcommands:
            subparser = ofrak_subcommand.create_parser(ofrak_subparsers)
            subparser.set_defaults(func=functools.partial(ofrak_subcommand.handler, ofrak_env))

    def parse_and_run(self, args: Sequence[str]):
        parsed = self.ofrak_parser.parse_args(args)
        if not hasattr(parsed, "func"):
            self.ofrak_parser.print_help()
            sys.exit(1)
        parsed.func(parsed)


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
