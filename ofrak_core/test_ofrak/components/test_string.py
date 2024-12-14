from pathlib import Path
import pytest

from typing import List

from ofrak import OFRAKContext
from ofrak.component.modifier import ModifierError
from ofrak.core import ProgramSection
from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.strings import (
    AsciiString,
    StringsUnpacker,
    StringPatchingConfig,
    StringPatchingModifier,
    StringFindReplaceConfig,
    StringFindReplaceModifier,
)


@pytest.fixture
def resource(ofrak_context: OFRAKContext) -> Resource:
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
    return ofrak_context.create_root_resource("text", test_binary, tags=(GenericBinary,))


@pytest.fixture
def executable_file():
    return Path(__file__).parent / "assets" / "string_test.out"


@pytest.fixture
def executable_strings(ofrak_context: OFRAKContext, executable_file) -> List[str]:
    root_resource = ofrak_context.create_root_resource_from_file(executable_file)
    root_resource.unpack_recursively()
    for d in root_resource.get_descendants(r_filter=ResourceFilter.with_tags(ProgramSection)):
        d.run(StringsUnpacker)
    descendants = list(
        root_resource.get_descendants_as_view(
            AsciiString,
            r_filter=ResourceFilter.with_tags(AsciiString),
        )
    )
    for d in descendants:
        assert d.text[:8] in d.resource.get_caption()
    return [string.Text for string in descendants]


def test_string_modifier(resource: Resource):
    config = StringPatchingConfig(10, "Oh hello there!")
    resource.run(StringPatchingModifier, config)
    patched_file = resource.get_data()
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


def test_string_modifier_null_terminated(resource: Resource):
    config = StringPatchingConfig(10, "Oh hello there!", null_terminate=True)
    resource.run(StringPatchingModifier, config)
    patched_file = resource.get_data()
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


def test_string_replace_modifier(resource: Resource):
    config = StringFindReplaceConfig(
        "me the way",
        "WHAT!!!",
    )
    resource.run(StringFindReplaceModifier, config)
    patched_file = resource.get_data()
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


def test_string_replace_modifier_no_overflow(resource: Resource):
    config = StringFindReplaceConfig("me the way", "WHAT!!!!!!!!!!!!", allow_overflow=False)
    with pytest.raises(ModifierError):
        resource.run(StringFindReplaceModifier, config)


def test_shortest_string_not_in_non_code(executable_strings: List[str]):
    assert "O" not in executable_strings


def test_short_string_in_non_code(executable_strings: List[str]):
    assert "h, hi" in executable_strings


def test_short_string_not_in_code(executable_strings: List[str]):
    # ASCII representation of shortString code from test file
    assert "AWL#<%" not in executable_strings


def test_long_string_in_none(executable_strings: List[str]):
    assert "You are tearing me apart, Lisa!" in executable_strings


def test_long_string_in_code(executable_strings: List[str]):
    # ASCII representation of longString code from test file
    assert "AWAWAWAWAWAWAWAWL#<%" in executable_strings


def test_strings_analyzer(ofrak_context):
    res = ofrak_context.create_root_resource(
        "test_strings_analyzer", b"Oh hi Marc!\x00", tags=(AsciiString,)
    )
    ascii_str = res.view_as(AsciiString)
    assert ascii_str.text == "Oh hi Marc!"
