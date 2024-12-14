from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

import argparse
import os
import subprocess
import sys
import pkg_resources
import yaml

DEFAULT_PYTHON_IMAGE = (
    "python:3.8-bullseye@sha256:e1cd369204123e89646f8c001db830eddfe3e381bd5c837df00141be3bd754cb"
)
BASE_DOCKERFILE = "base.Dockerfile"
FINISH_DOCKERFILE = "finish.Dockerfile"


class InstallTarget(Enum):
    INSTALL = "install"
    DEVELOP = "develop"


@dataclass
class OfrakImageConfig:
    registry: str
    base_image_name: str
    image_name: str
    image_revision: str
    packages_paths: List[str]
    build_base: bool
    build_finish: bool
    # Whether to supply --no-cache to docker build commands
    no_cache: bool
    extra_build_args: Optional[List[str]]
    install_target: InstallTarget
    cache_from: List[str]
    entrypoint: Optional[str]
    python_image: str

    def validate_serial_txt_existence(self):
        """
        Check that the potential serial.txt file in `extra_build_args` exists on the filesystem.
        Otherwise, raise an explicit error message.
        """
        if (
            self.extra_build_args is not None
            and "id=serial,src=serial.txt" in self.extra_build_args
            and not os.path.exists("serial.txt")
        ):
            print(
                "Error: file serial.txt not found.\n"
                "You need a valid BinaryNinja license file, and to extract the serial number from that file "
                "into a file named serial.txt in this directory.\n"
                "Refer to the documentation for more details."
            )
            sys.exit(1)


def main():
    config = parse_args()
    print(
        f"Building {BASE_DOCKERFILE}, {FINISH_DOCKERFILE} for {config.image_name} from: "
        f"{', '.join(config.packages_paths)}."
    )
    for package_path in config.packages_paths:
        check_package_contents(package_path)

    dockerfile_base = create_dockerfile_base(config)
    with open(BASE_DOCKERFILE, "w") as f:
        f.write(dockerfile_base)
    print(f"{BASE_DOCKERFILE} built.")

    dockerfile_finish = create_dockerfile_finish(config)
    with open(FINISH_DOCKERFILE, "w") as f:
        f.write(dockerfile_finish)
    print(f"{FINISH_DOCKERFILE} built.")

    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"

    if config.build_base:
        full_base_image_name = "/".join((config.registry, config.base_image_name))
        cache_args = []
        if config.cache_from is not None:
            for cache in config.cache_from:
                cache_args.append("--cache-from")
                cache_args.append(cache)
        base_command = [
            "docker",
            "build",
            "--build-arg",
            "BUILDKIT_INLINE_CACHE=1",
            "--cache-from",
            f"{full_base_image_name}:master",
            *cache_args,
            "-t",
            f"{full_base_image_name}:{config.image_revision}",
            "-t",
            f"{full_base_image_name}:latest",
            "-f",
            BASE_DOCKERFILE,
            ".",
        ]
        if config.no_cache:
            base_command.extend(["--no-cache"])
        # For secure build arguments
        if config.extra_build_args:
            base_command.extend(config.extra_build_args)
        try:
            subprocess.run(base_command, check=True, env=env)
        except subprocess.CalledProcessError as error:
            print(f"Error running command: '{' '.join(error.cmd)}'")
            print(f"Exit status: {error.returncode}")
            sys.exit(error.returncode)

    if config.build_finish:
        full_image_name = "/".join((config.registry, config.image_name))
        finish_command = [
            "docker",
            "build",
            "-t",
            f"{full_image_name}:{config.image_revision}",
            "-t",
            f"{full_image_name}:latest",
            "-f",
            FINISH_DOCKERFILE,
            "--build-arg",
            f"INSTALL_TARGET={config.install_target.value}",
            ".",
        ]
        if config.no_cache:
            finish_command.extend(["--no-cache"])
        try:
            subprocess.run(finish_command, check=True, env=env)
        except subprocess.CalledProcessError as error:
            print(f"Error running command: '{' '.join(error.cmd)}'")
            print(f"Exit status: {error.returncode}")
            sys.exit(error.returncode)


def parse_args() -> OfrakImageConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--base", action="store_true")
    parser.add_argument("--finish", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--target",
        choices=[InstallTarget.DEVELOP.value, InstallTarget.INSTALL.value],
        default=InstallTarget.DEVELOP.value,
    )
    parser.add_argument("--cache-from", action="append")
    args = parser.parse_args()
    with open(args.config) as file_handle:
        config_dict = yaml.safe_load(file_handle)
    if "image_revision" in config_dict:
        image_revision = config_dict["image_revision"]
    else:
        image_revision = (
            subprocess.check_output(["git", "rev-parse", "--short=8", "HEAD"])
            .decode("ascii")
            .strip()
        )
    image_config = OfrakImageConfig(
        config_dict["registry"],
        config_dict["base_image_name"],
        config_dict["image_name"],
        image_revision,
        config_dict["packages_paths"],
        args.base,
        args.finish,
        args.no_cache,
        config_dict.get("extra_build_args"),
        InstallTarget(args.target),
        args.cache_from,
        config_dict.get("entrypoint"),
        config_dict.get("python_image", DEFAULT_PYTHON_IMAGE),
    )
    image_config.validate_serial_txt_existence()
    return image_config


def check_package_contents(package_path: str):
    required_contents = [
        package_path,
        os.path.join(package_path, "Dockerstub"),
        os.path.join(package_path, "Makefile"),
    ]
    if not all([os.path.exists(content) for content in required_contents]):
        raise ValueError(
            f"Package or required files (Dockerstub, Makefile) do not exist for "
            f"{os.path.abspath(package_path)}"
        )
    return


def create_dockerfile_base(config: OfrakImageConfig) -> str:
    dockerfile_base_parts = [
        "# syntax = docker/dockerfile:1.3",
    ]

    # Support multi-stage builds
    for package_path in config.packages_paths:
        dockerstage_path = os.path.join(package_path, "Dockerstage")
        if not os.path.exists(dockerstage_path):
            continue
        with open(dockerstage_path) as file_handle:
            dockerstub = file_handle.read()
        # Cannot use ENV here because of multi-stage build FROM, so replace direclty in Docerkstage contents
        dockerstub = dockerstub.replace("$PACKAGE_DIR", package_path)
        dockerfile_base_parts += [f"### {dockerstage_path}", dockerstub]

    dockerfile_base_parts += [
        f"FROM {config.python_image}",
        "",
    ]

    requirement_suffixes = ["", "-non-pypi"]
    if config.install_target is InstallTarget.DEVELOP:
        requirement_suffixes += ["-docs", "-test"]

    for package_path in config.packages_paths:
        dockerstub_path = os.path.join(package_path, "Dockerstub")
        with open(dockerstub_path) as file_handle:
            dockerstub = file_handle.read()
        dockerfile_base_parts += [
            f"### {dockerstub_path}",
            f"ENV PACKAGE_PATH={package_path}",
            dockerstub,
        ]
        # Collect python dependencies
        python_reqs = []
        for suff in requirement_suffixes:
            requirements_path = os.path.join(package_path, f"requirements{suff}.txt")
            if not os.path.exists(requirements_path):
                continue
            with open(requirements_path) as requirements_handle:
                python_reqs += [
                    str(requirement)
                    for requirement in pkg_resources.parse_requirements(requirements_handle)
                ]
        if python_reqs:
            dockerfile_base_parts += [
                f"### Python dependencies from the {package_path} requirements file[s]",
                "RUN python3 -m pip install --upgrade pip &&\\",
                "   python3 -m pip install '" + "' '".join(python_reqs) + "'",
                "",
            ]

    return "\n".join(dockerfile_base_parts)


def create_dockerfile_finish(config: OfrakImageConfig) -> str:
    full_base_image_name = "/".join((config.registry, config.base_image_name))
    dockerfile_finish_parts = [
        f"FROM {full_base_image_name}:{config.image_revision}\n\n",
        f"ARG OFRAK_SRC_DIR=/\n",
    ]
    package_names = list()
    for package_path in config.packages_paths:
        package_name = os.path.basename(package_path)
        package_names.append(package_name)
        dockerfile_finish_parts.append(f"ADD {package_path} $OFRAK_SRC_DIR/{package_name}\n")
    dockerfile_finish_parts.append("\nWORKDIR /\n")
    dockerfile_finish_parts.append("ARG INSTALL_TARGET\n")
    develop_makefile = "\\n\\\n".join(
        [
            "$INSTALL_TARGET:",
            "\\n\\\n".join(
                [f"\t\\$(MAKE) -C {package_name} $INSTALL_TARGET" for package_name in package_names]
            ),
            "\\n",
        ]
    )
    dockerfile_finish_parts.append(f'RUN printf "{develop_makefile}" >> Makefile\n')
    dockerfile_finish_parts.append("RUN make $INSTALL_TARGET\n\n")
    test_names = " ".join([f"test_{package_name}" for package_name in package_names])
    finish_makefile = "\\n\\\n".join(
        [
            ".PHONY: test " + test_names,
            "test: " + test_names,
        ]
        + [
            f"test_{package_name}:\\n\\\n\t\\$(MAKE) -C {package_name} test"
            for package_name in package_names
        ]
        + ["\\n"]
    )
    dockerfile_finish_parts.append(f'RUN printf "{finish_makefile}" >> Makefile\n')
    if config.entrypoint is not None:
        dockerfile_finish_parts.append('SHELL ["/bin/bash", "-c"]\n')
        dockerfile_finish_parts.append(f"ENTRYPOINT {config.entrypoint}")
    return "".join(dockerfile_finish_parts)


if __name__ == "__main__":
    main()
