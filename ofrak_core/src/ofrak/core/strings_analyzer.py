import asyncio
from dataclasses import dataclass
from typing import Dict, Optional

from ofrak.component.analyzer import Analyzer
from ofrak.resource import Resource
from ofrak.model.component_model import ComponentConfig, ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributes


@dataclass
class StringsAnalyzerConfig(ComponentConfig):
    min_length: int = 8


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class StringsAttributes(ResourceAttributes):
    strings: Dict[int, str]


class _StringsToolDependency(ComponentExternalTool):
    def __init__(self):
        super().__init__(
            "strings",
            "https://linux.die.net/man/1/strings",
            "--help",
            apt_package="binutils",
            brew_package="binutils",
        )

    async def is_tool_installed(self) -> bool:
        try:
            cmd = [
                self.tool,
                self.install_check_arg,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            # ignore returncode because "strings --help" on Mac has returncode 1
            await proc.wait()
        except FileNotFoundError:
            return False

        return True


class StringsAnalyzer(Analyzer[Optional[StringsAnalyzerConfig], StringsAttributes]):
    targets = ()
    outputs = (StringsAttributes,)
    external_dependencies = (_StringsToolDependency(),)

    async def analyze(
        self, resource: Resource, config: Optional[StringsAnalyzerConfig] = None
    ) -> StringsAttributes:
        if config is None:
            config = StringsAnalyzerConfig()

        strings = dict()
        async with resource.temp_to_disk() as temp_path:
            proc = await asyncio.subprocess.create_subprocess_exec(
                "strings",
                "-t",
                "d",
                f"-{config.min_length}",
                temp_path,
                stdout=asyncio.subprocess.PIPE,
            )

            line = await proc.stdout.readline()  # type: ignore
            while line:
                line = line.decode("ascii").strip()
                try:
                    offset, string = line.split(" ", maxsplit=1)
                except ValueError as e:
                    # String consisted entirely of whitespace
                    line = await proc.stdout.readline()  # type: ignore
                    continue
                strings[int(offset)] = string
                line = await proc.stdout.readline()  # type: ignore
            await proc.wait()

        return StringsAttributes(strings)
