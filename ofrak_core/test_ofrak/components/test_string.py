import pytest

from ofrak import OFRAKContext
from ofrak.component.modifier import ModifierError
from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak.core.strings import (
    StringPatchingConfig,
    StringPatchingModifier,
    StringFindReplaceConfig,
    StringFindReplaceModifier,
)


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
