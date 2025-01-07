import asyncio
import re
from dataclasses import dataclass

from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier, ModifierError
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier, GenericText, GenericBinary
from ofrak.core.code_region import CodeRegion
from ofrak.core.filesystem import File
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import index
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak_type import Range


@dataclass
class StringPatchingConfig(ComponentConfig):
    """
    Dataclass required to apply a string patch with `StringPatchingModifier`. The configuration
    describes the `offset` where the patch is to be applied, and the `string` to patch in.

    :var offset: the offset at which to apply the patch
    :var string: the string to patch in
    """

    offset: int
    string: str
    null_terminate: bool = False


class StringPatchingModifier(Modifier[StringPatchingConfig]):
    """
    Patch a string in a resource at a given offset, based on the provided configuration.
    """

    id = b"StringPatchingModifier"
    targets = (GenericText,)

    async def modify(self, resource: Resource, config: StringPatchingConfig):
        new_data = config.string.encode("utf-8")
        if config.null_terminate:
            new_data += b"\x00"
        patch_config = BinaryPatchConfig(config.offset, new_data)
        await resource.run(BinaryPatchModifier, patch_config)


@dataclass
class StringFindReplaceConfig(ComponentConfig):
    """
    :var to_find: the string to search for
    :var replace_with: the string to pass in
    :var null_terminate: add a null terminator to the replacement if True
    :var allow_overflow: allow the replace string to overflow the found string if True
    """

    to_find: str
    replace_with: str
    null_terminate: bool = True
    allow_overflow: bool = False


class StringFindReplaceModifier(Modifier[StringFindReplaceConfig]):
    """
    Find and replace all instances of a given string with a replacement string.
    """

    targets = (GenericBinary, File)

    async def modify(self, resource: Resource, config: StringFindReplaceConfig) -> None:
        to_find = config.to_find.encode("utf-8")
        replace_with = config.replace_with.encode("utf-8") + (
            b"\x00" if config.null_terminate and config.replace_with[-1] != "\x00" else b""
        )
        if not config.allow_overflow and len(replace_with) > len(to_find):
            raise ModifierError(
                f"Original string is longer than the new string ({len(to_find)} < "
                f"{len(replace_with)})! Set config.allow_overflow = True to override this error. "
                f"If you expect that the string to replace is null-terminated, then an overflow "
                f"of one byte when config.null_terminate = True will not have any effect."
            )
        for offset in await resource.search_data(to_find):
            await resource.run(BinaryPatchModifier, BinaryPatchConfig(offset, replace_with))


@dataclass
class AsciiString(ResourceView):
    """
    Resource representing a C-style, NULL-terminated string of ASCII characters. The `text` string
    is not NULL-terminated.
    """

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
    """
    Extract the decoded string from a C-style, NULL-terminated string of ASCII characters.
    """

    targets = (AsciiString,)
    outputs = (AsciiString,)

    async def analyze(self, resource: Resource, config: None) -> AsciiString:
        raw_without_null_byte = (await resource.get_data()).rstrip(b"\x00")
        return AsciiString(raw_without_null_byte.decode("ascii"))


class StringsUnpacker(Unpacker[None]):
    """
    Unpack NULL-terminated strings of printable ASCII characters.
    """

    targets = ()  # Strings unpacker is slow, don't run by default.
    children = (AsciiString,)

    # match sequences of at least 2 (or 8 in CodeRegions) printable characters ending with NULL
    # printable characters defined as: ASCII between ' ' and '~', tab, newline, carriage return
    LONG_STRING_PATTERN = re.compile(b"([ -~\n\t\r]{8,})\x00")
    SHORT_STRING_PATTERN = re.compile(b"([ -~\n\t\r]{2,})\x00")

    async def unpack(self, resource: Resource, config: None) -> None:
        if resource.get_data_id() is None:
            return
        if resource.has_tag(CodeRegion):
            # code is less likely to have strings so more likely to have false positives
            pattern = self.LONG_STRING_PATTERN
        else:
            pattern = self.SHORT_STRING_PATTERN

        children = [
            resource.create_child_from_view(
                AsciiString(string.rstrip(b"\x00").decode("ascii")),
                data_range=Range.from_size(offset, len(string)),
            )
            for offset, string in await resource.search_data(pattern)
        ]

        await asyncio.gather(*children)
