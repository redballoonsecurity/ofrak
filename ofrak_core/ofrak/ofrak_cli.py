import functools
from abc import ABC, abstractmethod
from argparse import Namespace, ArgumentParser
from inspect import isabstract
from types import ModuleType
from typing import Dict, Optional, Type, List, Iterable, Set

from ofrak import OFRAK
from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import ComponentExternalTool
from synthol.injector import DependencyInjector


class OFRAKEnvironment:
    def __init__(self):
        self._ofrak = OFRAK()
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
            self._ofrak_packages = {
                pkg.__name__: pkg for pkg in self._ofrak.get_installed_ofrak_packages()
            }
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
            help="List installed OFRAK modules and/or components. By default, prints all "
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
        return deps_parser

    @staticmethod
    def handler(ofrak_env: OFRAKEnvironment, args: Namespace):
        dependencies = list()
        packages: Iterable[ModuleType]

        if args.package:
            packages = [ofrak_env.packages[pkg_name] for pkg_name in args.package]
        elif args.component:
            packages = []
        else:
            packages = ofrak_env.packages.values()

        if args.component:
            components = [ofrak_env.components[component_name] for component_name in args.component]
        elif args.package:
            components = []
        else:
            components = list(ofrak_env.components.values())

        for pkg in packages:
            components.extend(ofrak_env.components_by_package[pkg])

        if not components:
            return

        components_by_dep: Dict[ComponentExternalTool, Set[str]] = dict()
        for component in components:
            dep_list = ofrak_env.dependencies_by_component[component]
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


class OFRAKCommandLineInterface:
    def __init__(self, ofrak_env: OFRAKEnvironment, subcommands: List[OFRAKSubCommand]):
        self.ofrak_parser = ArgumentParser()
        ofrak_subparsers = self.ofrak_parser.add_subparsers(
            help="Command line utilities to use or configure OFRAK"
        )

        for ofrak_subcommand in subcommands:
            subparser = ofrak_subcommand.create_parser(ofrak_subparsers)
            subparser.set_defaults(func=functools.partial(ofrak_subcommand.handler, ofrak_env))

    def parse_and_run(self, args=None):
        args = self.ofrak_parser.parse_args(args)
        args.func(args)


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
