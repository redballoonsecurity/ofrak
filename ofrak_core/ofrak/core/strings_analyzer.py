import asyncio
import tempfile
from dataclasses import dataclass
from typing import Dict, Optional

from ofrak.model.viewable_tag_model import AttributesType


from ofrak.core import CodeRegion

from ofrak.core.program_section import ProgramSection

from ofrak.component.unpacker import Unpacker

from ofrak.component.analyzer import Analyzer
from ofrak.resource import Resource
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes, index
from ofrak.resource_view import ResourceView
from ofrak_type import Range


@dataclass
class StringsAnalyzerConfig(ComponentConfig):
    min_length: int = 8


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class StringsAttributes(ResourceAttributes):
    strings: Dict[int, str]


class StringsAnalyzer(Analyzer[Optional[StringsAnalyzerConfig], StringsAttributes]):
    targets = ()
    outputs = (StringsAttributes,)

    async def analyze(
        self, resource: Resource, config: Optional[StringsAnalyzerConfig] = None
    ) -> StringsAttributes:
        if config is None:
            config = StringsAnalyzerConfig()

        strings = dict()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(await resource.get_data())
            temp_file.flush()

            proc = await asyncio.subprocess.create_subprocess_exec(
                "strings",
                "-t",
                "d",
                f"-{config.min_length}",
                temp_file.name,
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


@dataclass
class AsciiString(ResourceView):
    text: str

    @index
    def Text(self) -> str:
        return self.text

    @classmethod
    def caption(cls, all_attributes) -> str:
        try:
            s = all_attributes[AttributesType[AsciiString]]
            return f"string: '{s.text}'"
        except KeyError:
            return super().caption(all_attributes)


class AsciiStringAnalyzer(Analyzer[None, AsciiString]):
    targets = (AsciiString,)
    outputs = (AsciiString,)

    async def analyze(self, resource: Resource, config: None) -> AsciiString:
        raw_without_null_byte = (await resource.get_data())[:-1]
        return AsciiString(raw_without_null_byte.decode("ascii"))


class StringsUnpacker(Unpacker[None]):
    targets = (ProgramSection,)  # TODO: Other reasonable targets?
    children = (AsciiString,)

    async def unpack(self, resource: Resource, config: None) -> None:
        if resource.get_data_id() is None:
            return
        if resource.has_tag(CodeRegion):
            # code is less likely to have strings so more likely to have false positives
            min_length = 8
        else:
            min_length = 2
        await resource.run(StringsAnalyzer, StringsAnalyzerConfig(min_length=min_length))
        analyzed_strings = await resource.analyze(StringsAttributes)

        children = [
            resource.create_child_from_view(
                AsciiString(string), data_range=Range.from_size(offset, len(string) + 1)
            )
            for offset, string in analyzed_strings.strings.items()
        ]

        await asyncio.gather(*children)
