import asyncio
import subprocess
import tempfile
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

    def is_tool_installed(self) -> bool:
        try:
            cmd = [
                self.tool,
                self.install_check_arg,
            ]
            subprocess.run(cmd)
        except FileNotFoundError:
            return False

        return True


class StringsAnalyzer(Analyzer[Optional[StringsAnalyzerConfig], StringsAttributes]):
    targets = ()
    outputs = (StringsAttributes,)
    external_dependencies = (_StringsToolDependency(),)

    def analyze(
        self, resource: Resource, config: Optional[StringsAnalyzerConfig] = None
    ) -> StringsAttributes:
        if config is None:
            config = StringsAnalyzerConfig()

        strings = dict()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource.get_data())
            temp_file.flush()

            proc = asyncio.subprocess.create_subprocess_exec(
                "strings",
                "-t",
                "d",
                f"-{config.min_length}",
                temp_file.name,
                stdout=asyncio.subprocess.PIPE,
            )

            line = proc.stdout.readline()  # type: ignore
            while line:
                line = line.decode("ascii").strip()
                try:
                    offset, string = line.split(" ", maxsplit=1)
                except ValueError as e:
                    # String consisted entirely of whitespace
                    line = proc.stdout.readline()  # type: ignore
                    continue
                strings[int(offset)] = string
                line = proc.stdout.readline()  # type: ignore
            proc.wait()

        return StringsAttributes(strings)
