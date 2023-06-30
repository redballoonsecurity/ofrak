import json
import os.path
from dataclasses import dataclass
from typing import Dict, Optional, Set

from ofrak.core.run_script_modifier import RunScriptModifier, RunScriptModifierConfig

from ofrak.resource import Resource

from ofrak.ofrak_context import OFRAKContext


class OfrakAdventure:
    """
    An OFRAK 'project'

    """

    def __init__(self):
        self.path: str = ""
        self.name: str = ""
        self.adventure_id: bytes = b""
        self.binaries: Dict[str, _OfrakAdventureBinary] = dict()
        self.scripts: Set[str] = set()

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

        scripts = raw_metadata["scripts"]
        binaries = {
            info["name"]: _OfrakAdventureBinary(
                set(info["associated_scripts"]), info.get("init_script")
            )
            for info in raw_metadata["binaries"]
        }
        name = raw_metadata["name"]
        adventure_id = raw_metadata["id"]

        adventure = OfrakAdventure()
        adventure.scripts = scripts
        adventure.binaries = binaries
        adventure.name = name
        adventure.adventure_id = adventure_id

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
            with open(os.path.join(self.path, "scripts", binary_metadata.init_script)) as f:
                code = f.read()
            await resource.run(RunScriptModifier, RunScriptModifierConfig(code))

        return resource


@dataclass
class _OfrakAdventureBinary:
    associated_scripts: Set[str]
    init_script: Optional[str]
