import functools
import logging
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser, _SubParsersAction, Namespace
from inspect import isabstract
from types import ModuleType
from typing import Dict, Iterable, List, Optional, Sequence, Type

from importlib_metadata import entry_points

from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import ComponentExternalTool
from ofrak.ofrak_context import OFRAKContext, OFRAK
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


class OfrakCommand(ABC):
    @abstractmethod
    def create_parser(self, ofrak_subparser: _SubParsersAction):
        raise NotImplementedError()

    @abstractmethod
    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):
        raise NotImplementedError()


class OfrakCommandRunsScript(OfrakCommand, ABC):
    """
    An OFRAK CLI command that needs to set up a full OFRAK Context and use it to run an OFRAK
    script. Has additional scaffolding to make this process easy.
    """

    @staticmethod
    def add_ofrak_arguments(command_subparser):
        # TODO: Add CLI arguments for additional modules to discover (e.g. ofrak_ghidra)
        command_subparser.add_argument(
            "--logging-level",
            "-l",
            help="Minimum level of messages to print",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default=OFRAK.DEFAULT_LOG_LEVEL,
        )
        command_subparser.add_argument(
            "--exclude-components-missing-dependencies",
            "-x",
            help="When initializing OFRAK, check each component's dependency and do not use any "
            "components missing some dependencies",
            action="store_true",
        )
        command_subparser.add_argument(
            "-b",
            "--backend",
            action="store",
            help="Set GUI server backend.",
            default=None,
        )

    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):
        if type(args.logging_level) is int:
            logging_level = args.logging_level
        else:
            logging_level = getattr(logging, args.logging_level.upper())
        ofrak = OFRAK(
            logging_level=logging_level,
            exclude_components_missing_dependencies=args.exclude_components_missing_dependencies,
        )

        if args.backend is not None:
            if args.backend.lower() == "binary-ninja":
                import ofrak_capstone  # type: ignore
                import ofrak_binary_ninja  # type: ignore

                ofrak.discover(ofrak_capstone)
                ofrak.discover(ofrak_binary_ninja)

            elif args.backend.lower() == "ghidra":
                import ofrak_ghidra  # type: ignore

                ofrak.discover(ofrak_ghidra)

            elif args.backend.lower() == "angr":
                import ofrak_capstone  # type: ignore
                import ofrak_angr  # type: ignore

                ofrak.discover(ofrak_capstone)
                ofrak.discover(ofrak_angr)
            else:
                logging.warning(
                    "No disassembler backend specified, so no disassembly will be possible"
                )

        ofrak.run(self.ofrak_func, args)

    @abstractmethod
    async def ofrak_func(self, ofrak_context: OFRAKContext, args: Namespace):
        raise NotImplementedError()


class OFRAKCommandLineInterface:
    def __init__(
        self,
        subcommands: Iterable[OfrakCommand],
        ofrak_env: OFRAKEnvironment = OFRAKEnvironment(),
    ):
        self.ofrak_parser = ArgumentParser(prog="ofrak")
        ofrak_subparsers = self.ofrak_parser.add_subparsers(
            help="Command line utilities to use or configure OFRAK"
        )

        for ofrak_subcommand in subcommands:
            subparser = ofrak_subcommand.create_parser(ofrak_subparsers)
            subparser.set_defaults(run=functools.partial(ofrak_subcommand.run, ofrak_env))

    def parse_and_run(self, args: Sequence[str]):
        parsed = self.ofrak_parser.parse_args(args)
        if not hasattr(parsed, "run"):
            self.ofrak_parser.print_help()
            sys.exit(1)
        parsed.run(parsed)
