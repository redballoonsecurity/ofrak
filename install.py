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

from build_image import InstallTarget


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


def main():
    config = parse_args()

    for package_path in config.packages_paths:
        check_package_contents(package_path)

    if not config.quiet:
        print(f"*** Checking whether npm and rollup are installed")
    check_executable(config, "npm")
    check_executable(config, "rollup")

    if not config.quiet:
        install_type = (
            "development environment " if config.install_target == InstallTarget.DEVELOP else ""
        )
        print(
            f"*** Installing OFRAK {install_type}for {config.python_command} from: "
            f"{', '.join(config.packages_paths)}."
        )
    for package_path in config.packages_paths:
        if not config.quiet:
            print(f"** Installing {package_path}")
        install_package(config, package_path)

    if config.dependency_mechanism == DependencyMechanism.NONE:
        pass
    elif config.dependency_mechanism == DependencyMechanism.SHOW:
        print("*** Checking for missing OFRAK dependencies")
        show_dependencies(config)
        show_install(config, "apt", "sudo apt install -y")
        show_install(config, "brew", "brew install")
    else:
        install_deps(config)
        if not config.quiet:
            print("*** Checking OFRAK dependencies that may need to be installed manually")
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
    args = parser.parse_args()
    python = shutil.which(args.python)
    if python is None:
        if not args.quiet:
            print(
                "*** Specify correct name or path of python binary to use, using either the "
                '"--python" command line argument, or the "OFRAK_INSTALL_PYTHON" environment'
                "variable.",
                file=sys.stderr,
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
            if not config.quiet:
                print(f"** {executable} not found, attempting to install")
            run_command(config, config.dep_install + [executable])
        elif config.dependency_mechanism in [DependencyMechanism.NONE, DependencyMechanism.SHOW]:
            if config.dependency_mechanism == DependencyMechanism.SHOW:
                print(f"** {executable} not found, please install manually,")
                print('** or use "--install_deps" / "OFRAK_INSTALL_DEPS"')
                print("** to have it be installed automatically for you:")
                print(f"**    apt:  sudo apt install -y {executable}")
                print(f"**    brew: brew install {executable}")
            raise FileNotFoundError(2, f"{executable} not found", executable)


def install_package(config: OfrakInstallConfig, package_path: str) -> None:
    if not config.quiet:
        print(f"** Installing from {package_path}")
    etc_dir = os.path.join(os.getenv("HOME", "/"), "etc")
    run_command(
        config,
        [
            "make",
            f"PYTHON={config.python_command}",
            f"PIP={config.python_command} -m pip",
            f"ETC={etc_dir}",
            "-C",
            package_path,
            config.install_target.value,
        ],
    )


def show_dependencies(config: OfrakInstallConfig) -> None:
    run_ofrak_command(config, ["deps", "--missing-only"])


def show_install(config: OfrakInstallConfig, dep: str, prefix: str) -> None:
    deps = run_ofrak_command(
        config,
        ["deps", "--missing-only", f"--packages-for={dep}"],
        True,
    )
    if deps:
        print(f"** If your system has {dep}, you can install some of the dependencies using:")
        print(f"**    {prefix} {deps}")


def install_deps(config: OfrakInstallConfig) -> None:
    if not config.quiet:
        print(
            "*** Installing those OFRAK dependencies that can be installed with "
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
    if not config.quiet:
        print("% " + " ".join(args))
    result = subprocess.run(args=args, capture_output=capture_out, check=True)
    return result.stdout.decode("ascii") if capture_out else None


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(f"*** Error running shell command, exit status: {error.returncode}", file=sys.stderr)
        sys.exit(error.returncode)
    except ValueError as error:
        print(f"*** Error: {error}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as error:
        print(f"*** Error: No such file or directory: {error.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"*** Unexpected exception: {error}", file=sys.stderr)
        sys.exit(1)
