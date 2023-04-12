import os
import pytest

from typing import List

from ofrak import OFRAKContext
from ofrak.component.modifier import ModifierError
from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.strings import (
    AsciiString,
    StringPatchingConfig,
    StringPatchingModifier,
    StringFindReplaceConfig,
    StringFindReplaceModifier,
)
import test_ofrak.components

STRING_FILE = os.path.join(test_ofrak.components.ASSETS_DIR, "string_test.out")


@pytest.fixture
async def resource(ofrak_context: OFRAKContext) -> Resource:
    test_binary = b"""
    Show me the way to go home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    """
    return await ofrak_context.create_root_resource("text", test_binary, tags=(GenericBinary,))


@pytest.fixture
async def executable_strings(ofrak_context: OFRAKContext) -> List[str]:
    root_resource = await ofrak_context.create_root_resource_from_file(STRING_FILE)
    await root_resource.unpack_recursively()
    descendants = list(
        await root_resource.get_descendants_as_view(
            AsciiString,
            r_filter=ResourceFilter.with_tags(AsciiString),
        )
    )
    return [string.Text for string in descendants]


async def test_string_modifier(resource: Resource):
    config = StringPatchingConfig(10, "Oh hello there!")
    await resource.run(StringPatchingModifier, config)
    patched_file = await resource.get_data()
    expected_contents = b"""
    Show Oh hello there!o home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    """
    assert patched_file == expected_contents


async def test_string_modifier_null_terminated(resource: Resource):
    config = StringPatchingConfig(10, "Oh hello there!", null_terminate=True)
    await resource.run(StringPatchingModifier, config)
    patched_file = await resource.get_data()
    expected_contents = b"""
    Show Oh hello there!\0 home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    Show me the way to go home.\0
    I would like to live in paradise.\n
    """
    assert patched_file == expected_contents


async def test_string_replace_modifier(resource: Resource):
    config = StringFindReplaceConfig(
        "me the way",
        "WHAT!!!",
    )
    await resource.run(StringFindReplaceModifier, config)
    patched_file = await resource.get_data()
    expected_contents = b"""
    Show WHAT!!!\0ay to go home.\0
    I would like to live in paradise.\n
    Show WHAT!!!\0ay to go home.\0
    I would like to live in paradise.\n
    Show WHAT!!!\0ay to go home.\0
    I would like to live in paradise.\n
    Show WHAT!!!\0ay to go home.\0
    I would like to live in paradise.\n
    """
    assert patched_file == expected_contents


async def test_string_replace_modifier_no_overflow(resource: Resource):
    config = StringFindReplaceConfig("me the way", "WHAT!!!!!!!!!!!!", allow_overflow=False)
    with pytest.raises(ModifierError):
        await resource.run(StringFindReplaceModifier, config)


async def test_shortest_string_not_in_non_code(executable_strings: List[str]):
    assert "O\x00" not in executable_strings


async def test_short_string_in_non_code(executable_strings: List[str]):
    assert "h, hi\x00" in executable_strings


async def test_short_string_not_in_code(executable_strings: List[str]):
    assert "AWL#<%\x00" not in executable_strings


async def test_long_string_in_none(executable_strings: List[str]):
    assert "You are tearing me apart, Lisa!\x00" in executable_strings


async def test_long_string_in_code(executable_strings: List[str]):
    assert "AWAWAWAWAWAWAWAWL#<%\x00" in executable_strings
