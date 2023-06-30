import binascii
import json
import os.path
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Set

from ofrak.core.run_script_modifier import RunScriptModifier, RunScriptModifierConfig

from ofrak.resource import Resource

from ofrak.ofrak_context import OFRAKContext


@dataclass
class _OfrakAdventureBinary:
    associated_scripts: Set[str]
    init_script: Optional[str]
    contents: bytes


class OfrakAdventure:
    """
    An OFRAK 'project'

    """

    def __init__(
        self,
        path: str,
        name: str,
        adventure_id: bytes,
        binaries: Dict[str, _OfrakAdventureBinary],
        scripts: Dict[str, str],
    ):
        self.path: str = path
        self.name: str = name
        self.adventure_id: bytes = adventure_id
        self.binaries: Dict[str, _OfrakAdventureBinary] = binaries
        self.scripts: Dict[str, str] = scripts

    @staticmethod
    def create(name: str, path: str) -> "OfrakAdventure":
        return OfrakAdventure(
            path,
            name,
            uuid.uuid4().bytes,
            {},
            {},
        )

    @staticmethod
    def init_from_path(path: str) -> "OfrakAdventure":
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
        readme_path = os.path.join(path, "README.md")
        binaries_path = os.path.join(path, "binaries")
        scripts_path = os.path.join(path, "scripts")

        if not all(
            [
                os.path.exists(metadata_path),
                os.path.exists(readme_path),
                os.path.exists(binaries_path),
                os.path.isdir(binaries_path),
                os.path.exists(scripts_path),
                os.path.isdir(scripts_path),
            ]
        ):
            raise ValueError(f"{path} has invalid structure to be an Adventure")

        with open(metadata_path) as f:
            raw_metadata = json.load(f)

        scripts = {}
        for script_name in raw_metadata["scripts"]:
            with open(os.path.join(path, "scripts", script_name)) as f:
                contents = f.read()
            scripts[script_name] = contents

        binaries = {}

        for info in raw_metadata["binaries"]:
            with open(os.path.join(path, "binaries", info["name"]), "rb") as f:
                contents = f.read()
            binaries[info["name"]] = _OfrakAdventureBinary(
                set(info["associated_scripts"]), info.get("init_script"), contents
            )
        name = raw_metadata["name"]
        adventure_id = binascii.unhexlify(raw_metadata["id"])

        adventure = OfrakAdventure(
            path,
            name,
            adventure_id,
            binaries,
            scripts,
        )

        return adventure

    async def init_adventure_binary(
        self, binary_name: str, ofrak_context: OFRAKContext
    ) -> Resource:
        if binary_name not in self.binaries:
            raise ValueError(f"{binary_name} is not a binary in Adventure {self.name}")

        binary_metadata = self.binaries[binary_name]

        resource = await ofrak_context.create_root_resource_from_file(
            os.path.join(self.path, "binaries", binary_name)
        )

        if binary_metadata.init_script:
            if binary_metadata.init_script not in self.scripts:
                raise ValueError(
                    f"Init script {binary_metadata.init_script} (for binary {binary_name}) not found in project!"
                )
            code = self.scripts[binary_metadata.init_script]
            await resource.run(RunScriptModifier, RunScriptModifierConfig(code))

        return resource
