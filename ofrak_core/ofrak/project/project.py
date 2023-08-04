import binascii
import json
import os.path
import uuid
from git import Repo
from dataclasses import dataclass
from typing import Dict, List, Optional

from ofrak.core.run_script_modifier import RunScriptModifier, RunScriptModifierConfig

from ofrak.resource import Resource

from ofrak.ofrak_context import OFRAKContext


@dataclass
class _OfrakProjectBinary:
    associated_scripts: List[str]
    init_script: Optional[str]


class OfrakProject:
    """
    An OFRAK 'project'

    """

    def __init__(
        self,
        path: str,
        name: str,
        project_id: bytes,
        binaries: Dict[str, _OfrakProjectBinary],
        scripts: List[str],
    ):
        self.path: str = path
        self.name: str = name
        self.project_id: bytes = project_id
        self.binaries: Dict[str, _OfrakProjectBinary] = binaries
        self.scripts: List[str] = scripts
        self.session_id = uuid.uuid4().bytes

    @property
    def metadata_path(self):
        return os.path.join(self.path, "metadata.json")

    @property
    def readme_path(self):
        return os.path.join(self.path, "README.md")

    @staticmethod
    def create(name: str, path: str) -> "OfrakProject":
        new_project = OfrakProject(
            path,
            name,
            uuid.uuid4().bytes,
            {},
            [],
        )

        os.makedirs(os.path.join(path, "scripts"), exist_ok=True)
        os.makedirs(os.path.join(path, "binaries"), exist_ok=True)

        new_project.write_metadata_to_disk()

        return new_project

    @staticmethod
    def clone_from_git(url: str, path: str) -> "OfrakProject":
        repo = Repo.clone_from(url, path)
        if not os.path.exists(path):
            raise ValueError(f"{path} does not exist")
        if not os.path.isdir(path):
            raise ValueError(f"{path} is not a directory")

        metadata_path = os.path.join(path, "metadata.json")
        binaries_path = os.path.join(path, "binaries")
        scripts_path = os.path.join(path, "scripts")

        if not all(
            [
                os.path.exists(metadata_path),
                os.path.exists(binaries_path),
                os.path.isdir(binaries_path),
                os.path.exists(scripts_path),
                os.path.isdir(scripts_path),
            ]
        ):
            raise ValueError(f"{path} has invalid structure to be an Project")

        with open(metadata_path) as f:
            raw_metadata = json.load(f)

        scripts = [script["name"] for script in raw_metadata["scripts"]]

        binaries = {}

        for binary_name, info in raw_metadata["binaries"].items():
            binaries[binary_name] = _OfrakProjectBinary(
                info["associated_scripts"], info.get("init_script")
            )
        name = raw_metadata["name"]
        project_id = binascii.unhexlify(raw_metadata["project_id"])
        project = OfrakProject(
            path,
            name,
            project_id,
            binaries,
            scripts,
        )

        return project

    @staticmethod
    def init_from_path(path: str) -> "OfrakProject":
        """

        Assume path points to a directory with the following structure:
        (top-level directory)
        |-metadata.json
        |-README.md
        |--binaries
        |   |-binary1.bin
        |   | ...
        |--scripts
            |-script1.py
            | ...

        :param path:
        :return:
        """
        if not os.path.exists(path):
            raise ValueError(f"{path} does not exist")
        if not os.path.isdir(path):
            raise ValueError(f"{path} is not a directory")

        metadata_path = os.path.join(path, "metadata.json")
        binaries_path = os.path.join(path, "binaries")
        scripts_path = os.path.join(path, "scripts")

        if not all(
            [
                os.path.exists(metadata_path),
                os.path.exists(binaries_path),
                os.path.isdir(binaries_path),
                os.path.exists(scripts_path),
                os.path.isdir(scripts_path),
            ]
        ):
            raise ValueError(f"{path} has invalid structure to be an Project")

        with open(metadata_path) as f:
            raw_metadata = json.load(f)

        scripts = [script["name"] for script in raw_metadata["scripts"]]

        binaries = {}

        for binary_name, info in raw_metadata["binaries"].items():
            binaries[binary_name] = _OfrakProjectBinary(
                info["associated_scripts"], info.get("init_script")
            )
        name = raw_metadata["name"]
        project_id = binascii.unhexlify(raw_metadata["project_id"])
        project = OfrakProject(
            path,
            name,
            project_id,
            binaries,
            scripts,
        )

        return project

    def script_path(self, script_name, check: bool = True) -> str:
        if check and script_name not in self.scripts:
            raise ValueError(f"Script {script_name} is not a script in this Project")
        p = os.path.join(self.path, "scripts", script_name)
        if check and not os.path.exists(p):
            raise ValueError(
                f"Script {script_name} is known to this Project but is not on disk "
                f"(looked at {p})"
            )
        return p

    def binary_path(self, binary_name, check: bool = True) -> str:
        if check and binary_name not in self.binaries:
            raise ValueError(f"Binary {binary_name} is not a binary in this Project")
        p = os.path.join(self.path, "binaries", binary_name)
        if check and not os.path.exists(p):
            raise ValueError(
                f"Binary {binary_name} is known to this Project but is not on disk "
                f"(looked at {p})"
            )
        return p

    async def init_adventure_binary(
        self, binary_name: str, script_name: str, ofrak_context: OFRAKContext
    ) -> Resource:
        binary_metadata = self.binaries[binary_name]
        resource = await ofrak_context.create_root_resource_from_file(self.binary_path(binary_name))

        if script_name is not None:
            with open(self.script_path(script_name)) as f:
                code = f.read()
            await resource.run(RunScriptModifier, RunScriptModifierConfig(code))

        return resource

    def write_metadata_to_disk(self):
        metadata = {
            "name": self.name,
            "project_id": self.project_id.hex(),
            "scripts": [
                {
                    "name": script_name,
                }
                for script_name in self.scripts
            ],
            "binaries": {
                binary_name: {
                    "init_script": binary_info.init_script,
                    "associated_scripts": binary_info.associated_scripts,
                }
                for binary_name, binary_info in self.binaries.items()
            },
        }
        with open(os.path.join(self.path, "metadata.json"), "w") as f:
            json.dump(metadata, f)

    def get_saved_metadata(self):
        with open(os.path.join(self.path, "metadata.json")) as f:
            data = json.load(f)
            data["session_id"] = self.session_id.hex()
            return data

    def get_current_metadata(self):
        return {
            "name": self.name,
            "project_id": self.project_id.hex(),
            "session_id": self.session_id.hex(),
            "scripts": [
                {
                    "name": script_name,
                }
                for script_name in self.scripts
            ],
            "binaries": {
                binary_name: {
                    "init_script": binary_info.init_script,
                    "associated_scripts": binary_info.associated_scripts,
                }
                for binary_name, binary_info in self.binaries.items()
            },
        }

    def add_binary(self, name: str, contents: bytes):
        self.binaries[name] = _OfrakProjectBinary([], None)
        os.makedirs(os.path.join(self.path, "binaries"), exist_ok=True)
        with open(self.binary_path(name, check=False), "wb+") as f:
            f.write(contents)

    def add_script(self, name: str, script_contents: str):
        self.scripts.append(name)
        os.makedirs(os.path.join(self.path, "scripts"), exist_ok=True)
        with open(self.script_path(name, check=False), "w+") as f:
            f.write(script_contents)

    def update_binary_data(self, name: str, init: str = None, associated: List[str] = None):
        binary = self._get_binary(name)
        if init is not None:
            binary.init_script = init
        if associated is not None:
            binary.associated_scripts = associated

    def delete_binary(self, name: str):
        self.binaries.pop(name)

    def delete_script(self, name: str):
        self.scripts.remove(name)

    def reset_project(self):
        path = self.path
        if not os.path.exists(path):
            raise ValueError(f"{path} does not exist")
        if not os.path.isdir(path):
            raise ValueError(f"{path} is not a directory")

        metadata_path = os.path.join(path, "metadata.json")
        binaries_path = os.path.join(path, "binaries")
        scripts_path = os.path.join(path, "scripts")

        if not all(
            [
                os.path.exists(metadata_path),
                os.path.exists(binaries_path),
                os.path.isdir(binaries_path),
                os.path.exists(scripts_path),
                os.path.isdir(scripts_path),
            ]
        ):
            raise ValueError(f"{path} has invalid structure to be an Project")

        with open(metadata_path) as f:
            raw_metadata = json.load(f)

        self.scripts = [script["name"] for script in raw_metadata["scripts"]]

        self.binaries = {}

        for binaryName, info in raw_metadata["binaries"].items():
            self.binaries[binaryName] = _OfrakProjectBinary(
                info["associated_scripts"], info.get("init_script")
            )
        self.name = raw_metadata["name"]
        self.project_id = binascii.unhexlify(raw_metadata["project_id"])

    def _get_binary(self, name):
        if not name in self.binaries.keys():
            raise ValueError(f"Binary with the name {name} does not exist")
        return self.binaries[name]
