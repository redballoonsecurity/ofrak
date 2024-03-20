#!/usr/bin/env python3
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

import argparse
import os
import subprocess
import sys
import yaml
import shutil
import logging

from build_image import InstallTarget

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class DependencyMechanism(Enum):
    NONE = "none"
    SHOW = "show"
    APT = "apt"
    BREW = "brew"


@dataclass
class OfrakInstallConfig:
    packages_paths: List[str]
    python_command: str
    install_target: InstallTarget
    dependency_mechanism: DependencyMechanism
    dep_install: List[str]
    quiet: bool
    run_tests: bool


def main():
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("*** %(msg)s")
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)

    config = parse_args()

    for package_path in config.packages_paths:
        check_package_contents(package_path)

    LOGGER.info(f"Checking whether npm is installed")
    check_executable(config, "npm")

    install_type = (
        "development environment " if config.install_target == InstallTarget.DEVELOP else ""
    )
    LOGGER.info(
        f"Installing OFRAK {install_type}for {config.python_command} from: "
        f"{', '.join(config.packages_paths)}."
    )
    for package_path in config.packages_paths:
        install_package(config, package_path)

    if config.dependency_mechanism == DependencyMechanism.NONE:
        pass
    elif config.dependency_mechanism == DependencyMechanism.SHOW:
        LOGGER.info("Checking for missing OFRAK dependencies")
        show_dependencies(config)
        show_install(config, "apt", "sudo apt install -y")
        show_install(config, "brew", "brew install")
    else:
        install_deps(config)
        LOGGER.info("Checking OFRAK dependencies that may need to be installed manually")
        if not config.quiet:
            show_dependencies(config)


def parse_args() -> OfrakInstallConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        help="Path to a .yml configuration file specifying which OFRAK packages to install",
        required=True,
    )
    parser.add_argument(
        "--target",
        choices=[InstallTarget.DEVELOP.value, InstallTarget.INSTALL.value],
        default=InstallTarget.DEVELOP.value,
        help='Installation type. Use "install" for regular installation, and "develop" to install in '
        'editable mode (i.e. setuptools "develop mode") from the source tree paths, and include '
        'development (test, build documentation, etc) dependencies. Defaults to "develop"',
    )
    parser.add_argument(
        "--python",
        default=os.getenv("OFRAK_INSTALL_PYTHON", "python3"),
        help="Path to, or name of the python executable to install OFRAK for. Defaults to the value of"
        'the "OFRAK_INSTALL_PYTHON" environment variable if set, and "python3", if not',
    )
    parser.add_argument(
        "--install_deps",
        choices=[
            DependencyMechanism.NONE.value,
            DependencyMechanism.SHOW.value,
            DependencyMechanism.APT.value,
            DependencyMechanism.BREW.value,
        ],
        default=os.getenv("OFRAK_INSTALL_DEPS", DependencyMechanism.SHOW.value),
        help='Method for installing non-pip dependencies. One of: "none" - do not install, "show" - '
        'show how to install them, but do not install automatically, "apt" - install using APT '
        '(requires sudo), "brew" - install using brew. Defaults to the value of the '
        '"OFRAK_INSTALL_DEPS" environment variable if set, and "show", if not',
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Reduce verbosity")
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run OFRAK tests after install. Can also be enabled by setting the OFRAK_TEST_AFTER_INSTALL environment valiable to a non-empty value",
    )
    args = parser.parse_args()
    if args.quiet:
        LOGGER.setLevel(logging.ERROR)
    python = shutil.which(args.python)
    if python is None:
        LOGGER.critical(
            "Specify correct name or path of python binary to use, using either the "
            '"--python" command line argument, or the "OFRAK_INSTALL_PYTHON" environment variable.',
        )
        raise ValueError(f"{args.python} not found")
    with open(args.config) as file_handle:
        config_dict = yaml.safe_load(file_handle)
    if args.install_deps == "apt":
        install_command = ["sudo", "apt", "install", "-y"]
    elif args.install_deps == "brew":
        install_command = ["brew", "install"]
    else:
        install_command = []
    install_config = OfrakInstallConfig(
        packages_paths=config_dict["packages_paths"],
        python_command=python,
        install_target=InstallTarget(args.target),
        dependency_mechanism=DependencyMechanism(args.install_deps),
        quiet=args.quiet,
        dep_install=install_command,
        run_tests=args.test or bool(os.getenv("OFRAK_TEST_AFTER_INSTALL", "")),
    )
    return install_config


def check_package_contents(package_path: str):
    for content in [package_path, os.path.join(package_path, "Makefile")]:
        if not os.path.exists(content):
            raise ValueError(f"Required path {content} do not exist")
    return


def check_executable(config: OfrakInstallConfig, executable: str) -> None:
    if shutil.which(executable) is None:
        if config.dependency_mechanism in [DependencyMechanism.APT, DependencyMechanism.BREW]:
            LOGGER.warning(f"{executable} not found, attempting to install")
            run_command(config, config.dep_install + [executable])
        elif config.dependency_mechanism in [DependencyMechanism.NONE, DependencyMechanism.SHOW]:
            if config.dependency_mechanism == DependencyMechanism.SHOW:
                LOGGER.critical(
                    f"{executable} not found, please install manually, or use"
                    ' "--install_deps" / "OFRAK_INSTALL_DEPS" to have it be installed automatically'
                    f' for you: with apt: "sudo apt install -y {executable}";'
                    f' with brew: "brew install {executable}"'
                )
            raise FileNotFoundError(2, f"{executable} not found", executable)


def install_package(config: OfrakInstallConfig, package_path: str) -> None:
    LOGGER.info(f"Installing from {package_path}")
    if os.path.exists(os.path.join(package_path, "package.json")):
        run_command(config, ["make", "-C", package_path, "npm_install_build"])
    run_command(
        config,
        [
            "make",
            f"PYTHON={config.python_command}",
            f"PIP={config.python_command} -m pip",
            "-C",
            package_path,
            config.install_target.value,
        ],
    )
    if config.run_tests:
        run_command(config, [config.python_command, "-m", "pip", "check"])
        run_command(
            config,
            [
                "make",
                f"PYTHON={config.python_command}",
                "-C",
                package_path,
                "test",
            ],
        )


def show_dependencies(config: OfrakInstallConfig) -> None:
    missing_deps = run_ofrak_command(config, ["deps", "--missing-only"], capture_out=True)
    if missing_deps:
        print("\n*** Some optional OFRAK dependencies are missing. ***")
        print(
            "To get full mileage out of OFRAK, you may want to also install some of the following:"
        )
        print(missing_deps.rstrip())


def show_install(config: OfrakInstallConfig, dep: str, prefix: str) -> None:
    deps = run_ofrak_command(
        config,
        ["deps", "--missing-only", f"--packages-for={dep}"],
        True,
    )
    if deps:
        deps = deps.strip().replace("\n", " ")
        print(
            f"** If your system has {dep}, you can install some of the above missing dependencies using:"
        )
        print(f"**    {prefix} {deps}")


def install_deps(config: OfrakInstallConfig) -> None:
    LOGGER.info(
        "Installing those OFRAK dependencies that can be installed with "
        + config.dependency_mechanism.value
    )
    deps = run_ofrak_command(
        config,
        ["deps", "--missing-only", f"--packages-for={config.dependency_mechanism.value}"],
        True,
    )
    assert deps is not None
    run_command(config, config.dep_install + deps.split())


def run_ofrak_command(
    config: OfrakInstallConfig, args: List[str], capture_out=False
) -> Optional[str]:
    return run_command(config, [config.python_command, "-m", "ofrak"] + args, capture_out)


def run_command(config: OfrakInstallConfig, args: List[str], capture_out=False) -> Optional[str]:
    (LOGGER.debug if capture_out else LOGGER.info)("% " + " ".join(args))
    result = subprocess.run(args=args, capture_output=capture_out, check=True)
    return result.stdout.decode("ascii") if capture_out else None


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        LOGGER.critical(f"Error running shell command, exit status: {error.returncode}")
        sys.exit(error.returncode)
    except ValueError as error:
        LOGGER.critical(f"Error: {error}")
        sys.exit(1)
    except FileNotFoundError as error:
        LOGGER.critical(f"Error: No such file or directory: {error.filename}")
        sys.exit(1)
    except Exception as error:
        LOGGER.critical(f"Unexpected exception: {error}")
        sys.exit(1)
