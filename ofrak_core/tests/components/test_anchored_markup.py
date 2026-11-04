"""
This module tests anchor-based markup: renaming functions with RenameComplexBlockModifier, and
naming and commenting the functions found by string anchors with ApplyAnchoredMarkupModifier.

Requirements Mapping:
- REQ2.6
- REQ3.4
"""
import json
import os

import pytest

from ofrak import OFRAKContext, ResourceFilter
from ofrak.core import (
    AnalystNameAttributes,
    Anchor,
    AnchorResolutionReport,
    AnchorType,
    ApplyAnchoredMarkupConfig,
    ApplyAnchoredMarkupModifier,
    CommentsAttributes,
    ComplexBlock,
    Program,
    ReferencedDataUnavailableError,
    RenameComplexBlockModifier,
    RenameComplexBlockModifierConfig,
    get_function_string_references,
    load_anchor_set,
    parse_anchor_set,
)
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource import MultipleResourcesFoundError
from ofrak.service.serialization.pjson import PJSONSerializationService
from ofrak_type.error import NotFoundError
from pytest_ofrak import ASSETS_DIR as PYTEST_OFRAK_ASSETS_DIR
from .re_markup_experiment import ASSETS_DIR, BUILD_A, analyze_build, load_ground_truth

ANCHOR_SET = os.path.join(ASSETS_DIR, "lua-anchors.yml")
# main() of hello.out, from its symbol table
HELLO_MAIN_VADDR = 0x4004C4
HELLO_MAIN_SIZE = 25


async def test_rename_complex_block(ofrak_context: OFRAKContext):
    """
    Test renaming a function of a real binary with RenameComplexBlockModifier (REQ3.4).

    This test verifies that:
    - The complex block view and the stored model get the new name
    - The virtual address, size and data of the complex block do not change
    - The ComplexBlock.Symbol index follows the new name, so Program.get_function_complex_block
      finds the function by its new name and not by its old one
    - The rename is recorded as an analyst's name
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    program = await root.view_as(Program)
    code_region = await program.get_code_region_for_vaddr(HELLO_MAIN_VADDR)
    main = ComplexBlock(HELLO_MAIN_VADDR, HELLO_MAIN_SIZE, "FUN_004004c4")
    main_resource = await code_region.create_child_region(main)
    main_data = await main_resource.get_data()

    await main_resource.run(RenameComplexBlockModifier, RenameComplexBlockModifierConfig("main"))

    renamed = await main_resource.view_as(ComplexBlock)
    assert (renamed.virtual_address, renamed.size, renamed.name) == (
        HELLO_MAIN_VADDR,
        HELLO_MAIN_SIZE,
        "main",
    )
    assert await main_resource.get_data() == main_data
    stored = await ofrak_context.resource_service.get_by_id(main_resource.get_id())
    assert stored.get_attributes(AttributesType[ComplexBlock]).name == "main"  # type: ignore
    found = await program.get_function_complex_block("main")
    assert found.resource.get_id() == main_resource.get_id()
    with pytest.raises(NotFoundError):
        await program.get_function_complex_block("FUN_004004c4")
    assert main_resource.get_attributes(AnalystNameAttributes).name == "main"


async def test_rename_complex_block_rejects_empty_name(ofrak_context: OFRAKContext):
    """
    Test that a complex block cannot be renamed to an empty name (REQ3.4).
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    program = await root.view_as(Program)
    code_region = await program.get_code_region_for_vaddr(HELLO_MAIN_VADDR)
    main_resource = await code_region.create_child_region(
        ComplexBlock(HELLO_MAIN_VADDR, HELLO_MAIN_SIZE, "main")
    )
    with pytest.raises(ValueError, match="empty name"):
        await main_resource.run(RenameComplexBlockModifier, RenameComplexBlockModifierConfig(""))


async def test_apply_anchored_markup(ghidra_ofrak_context: OFRAKContext):
    """
    Test resolving string anchors on a real binary with ApplyAnchoredMarkupModifier (REQ2.6).

    This test verifies that:
    - A string referenced by one known function renames and comments exactly that function
    - A string the program does not reference is a miss
    - A string referenced by several functions is ambiguous, and none of them is renamed
    - Two differently-named anchors resolving to the same function are both ambiguous
    - The outcome is recorded in an AnchorResolutionReport
    - The rename persists: the function is found by its new name, and its stored model has it
    - Applying the same anchors again changes nothing, and does not duplicate the comment
    """
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    ground_truth = load_ground_truth(BUILD_A)
    program = await root.view_as(Program)
    checkversion_vaddr = ground_truth.unique_vaddr("luaL_checkversion_")
    argerror_vaddr = ground_truth.unique_vaddr("luaL_argerror")
    name_users = sorted(
        vaddr
        for vaddr, texts in (await get_function_string_references(program)).items()
        if "__name" in texts
    )
    assert ground_truth.unique_vaddr("luaL_typeerror") in name_users
    assert ground_truth.unique_vaddr("luaL_tolstring") in name_users
    names_before = {
        complex_block.virtual_address: complex_block.name
        for complex_block in await root.get_descendants_as_view(
            ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
    }
    config = ApplyAnchoredMarkupConfig(
        [
            Anchor(
                "check_lua_version",
                AnchorType.STRING,
                "core and library have incompatible numeric types",
                "Checks the numeric types of the core and the library",
            ),
            Anchor("not_in_lua", AnchorType.STRING, "This string is not in the Lua interpreter"),
            Anchor("uses_name_field", AnchorType.STRING, "__name", "Should not be applied"),
            Anchor("argerror_1", AnchorType.STRING, "bad argument #%d (%s)"),
            Anchor("argerror_2", AnchorType.STRING, "calling '%s' on bad self (%s)"),
        ]
    )

    await root.run(ApplyAnchoredMarkupModifier, config)

    report = root.get_attributes(AnchorResolutionReport)
    assert report.hits == {"check_lua_version": (checkversion_vaddr,)}
    assert report.misses == ("not_in_lua",)
    assert report.missing_strings == {"not_in_lua": ("This string is not in the Lua interpreter",)}
    assert report.ambiguous == {
        "argerror_1": (argerror_vaddr,),
        "argerror_2": (argerror_vaddr,),
        "uses_name_field": tuple(name_users),
    }
    renamed = await program.get_function_complex_block("check_lua_version")
    assert renamed.virtual_address == checkversion_vaddr
    assert renamed.resource.get_attributes(CommentsAttributes).comments == {
        None: ["Checks the numeric types of the core and the library"]
    }
    stored = await ghidra_ofrak_context.resource_service.get_by_id(renamed.resource.get_id())
    assert stored.get_attributes(AttributesType[ComplexBlock]).name == "check_lua_version"  # type: ignore
    names_after = {
        complex_block.virtual_address: complex_block.name
        for complex_block in await root.get_descendants_as_view(
            ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
    }
    assert {vaddr for vaddr in names_after if names_after[vaddr] != names_before[vaddr]} == {
        checkversion_vaddr
    }

    await root.run(ApplyAnchoredMarkupModifier, config)
    renamed = await program.get_function_complex_block("check_lua_version")
    assert renamed.resource.get_attributes(CommentsAttributes).comments == {
        None: ["Checks the numeric types of the core and the library"]
    }
    assert root.get_attributes(AnchorResolutionReport) == report


async def test_apply_anchored_markup_to_all_matches(ghidra_ofrak_context: OFRAKContext):
    """
    Test that apply_to_all applies an anchor to every function it matches (REQ2.6).

    This test verifies that:
    - Every function referencing the anchor's string gets its name and comment
    - The anchor is a hit for all of them
    """
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    program = await root.view_as(Program)
    name_users = sorted(
        vaddr
        for vaddr, texts in (await get_function_string_references(program)).items()
        if "__name" in texts
    )

    await root.run(
        ApplyAnchoredMarkupModifier,
        ApplyAnchoredMarkupConfig(
            [Anchor("uses_name_field", AnchorType.STRING, "__name", "Reads the __name field")],
            apply_to_all=True,
        ),
    )

    assert root.get_attributes(AnchorResolutionReport).hits == {
        "uses_name_field": tuple(name_users)
    }
    with pytest.raises(MultipleResourcesFoundError):
        await program.get_function_complex_block("uses_name_field")
    for complex_block in await root.get_descendants_as_view(
        ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
    ):
        is_user = complex_block.virtual_address in name_users
        assert (complex_block.name == "uses_name_field") == is_user
        if is_user:
            comments = complex_block.resource.get_attributes(CommentsAttributes).comments
            assert comments == {None: ["Reads the __name field"]}


async def test_anchors_with_the_same_name(ghidra_ofrak_context: OFRAKContext):
    """
    Test that several anchors with the same name identify one function together (REQ2.6).

    This test verifies that:
    - Two anchors on strings of the same function back each other up: the name is a hit, even
      if one of the strings matches no function, which is reported
    - An anchor on a string several functions reference is narrowed down to the one function
      another anchor with the same name matches
    - Anchors with the same name that match different functions make the name ambiguous, with
      the functions they match as candidates, and none of them is renamed
    - Every anchor's comment is added to the function
    """
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    ground_truth = load_ground_truth(BUILD_A)
    program = await root.view_as(Program)
    argerror_vaddr = ground_truth.unique_vaddr("luaL_argerror")
    typeerror_vaddr = ground_truth.unique_vaddr("luaL_typeerror")
    checkversion_vaddr = ground_truth.unique_vaddr("luaL_checkversion_")

    await root.run(
        ApplyAnchoredMarkupModifier,
        ApplyAnchoredMarkupConfig(
            [
                Anchor("argerror", AnchorType.STRING, "bad argument #%d (%s)", "Raises an error"),
                Anchor("argerror", AnchorType.STRING, "calling '%s' on bad self (%s)"),
                Anchor("argerror", AnchorType.STRING, "This string is not in Lua", "About self"),
                Anchor("typeerror", AnchorType.STRING, "__name"),
                Anchor("typeerror", AnchorType.STRING, "%s expected, got %s"),
                Anchor("mixed_up", AnchorType.STRING, "bad argument #%d to '%s' (%s)"),
                Anchor(
                    "mixed_up",
                    AnchorType.STRING,
                    "core and library have incompatible numeric types",
                ),
            ]
        ),
    )

    report = root.get_attributes(AnchorResolutionReport)
    assert report.hits == {"argerror": (argerror_vaddr,), "typeerror": (typeerror_vaddr,)}
    assert report.ambiguous == {"mixed_up": tuple(sorted((argerror_vaddr, checkversion_vaddr)))}
    assert report.misses == ()
    assert report.missing_strings == {"argerror": ("This string is not in Lua",)}
    argerror = await program.get_function_complex_block("argerror")
    assert argerror.virtual_address == argerror_vaddr
    assert argerror.resource.get_attributes(CommentsAttributes).comments == {
        None: ["Raises an error", "About self"]
    }
    with pytest.raises(NotFoundError):
        await program.get_function_complex_block("mixed_up")


async def test_anchored_markup_keeps_analyst_names(ghidra_ofrak_context: OFRAKContext):
    """
    Test that anchors do not overwrite a name an analyst already gave a function (REQ2.6).

    This test verifies that:
    - An anchor resolving to a function an analyst named otherwise is a conflict, and changes
      neither the function's name nor its comments
    - An anchor with the name the function already has is applied
    """
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    ground_truth = load_ground_truth(BUILD_A)
    program = await root.view_as(Program)
    checkversion_vaddr = ground_truth.unique_vaddr("luaL_checkversion_")
    argerror_vaddr = ground_truth.unique_vaddr("luaL_argerror")
    complex_blocks = {
        complex_block.virtual_address: complex_block
        for complex_block in await root.get_descendants_as_view(
            ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
    }
    for vaddr, name in ((checkversion_vaddr, "my_checkversion"), (argerror_vaddr, "argerror")):
        await complex_blocks[vaddr].resource.run(
            RenameComplexBlockModifier, RenameComplexBlockModifierConfig(name)
        )

    await root.run(
        ApplyAnchoredMarkupModifier,
        ApplyAnchoredMarkupConfig(
            [
                Anchor(
                    "check_lua_version",
                    AnchorType.STRING,
                    "core and library have incompatible numeric types",
                    "Should not be applied",
                ),
                Anchor("argerror", AnchorType.STRING, "bad argument #%d (%s)", "Raises an error"),
            ]
        ),
    )

    report = root.get_attributes(AnchorResolutionReport)
    assert report.conflicts == {"check_lua_version": (checkversion_vaddr,)}
    assert report.hits == {"argerror": (argerror_vaddr,)}
    kept = await program.get_function_complex_block("my_checkversion")
    assert not kept.resource.has_attributes(CommentsAttributes)
    argerror = await program.get_function_complex_block("argerror")
    assert argerror.resource.get_attributes(CommentsAttributes).comments == {
        None: ["Raises an error"]
    }


async def test_apply_committed_anchor_set(ghidra_ofrak_context: OFRAKContext):
    """
    Test applying the committed anchor set for Lua to a real build (REQ2.6).

    This test verifies that:
    - Every anchor of the set names the function it is documented to name, according to the
      build's symbol table, except the deliberately ambiguous one
    """
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    ground_truth = load_ground_truth(BUILD_A)
    config = await load_anchor_set(ANCHOR_SET)

    await root.run(ApplyAnchoredMarkupModifier, config)

    report = root.get_attributes(AnchorResolutionReport)
    assert report.misses == ()
    assert report.missing_strings == {}
    assert set(report.ambiguous) == {"metatable_name_user"}
    assert report.hits == {
        anchor.name: (ground_truth.unique_vaddr(anchor.name),)
        for anchor in config.anchors
        if anchor.name != "metatable_name_user"
    }


async def test_apply_anchored_markup_without_data_references(ofrak_context: OFRAKContext):
    """
    Test that anchored markup fails loudly when no backend provides data cross-references
    (REQ2.6).
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    with pytest.raises(ReferencedDataUnavailableError):
        await root.run(
            ApplyAnchoredMarkupModifier,
            ApplyAnchoredMarkupConfig([Anchor("main", AnchorType.STRING, "Hello World!")]),
        )


async def test_load_anchor_set():
    """
    Test loading the committed YAML anchor set, and the same set written as JSON (REQ2.6).

    This test verifies that:
    - Anchors get their name, value and comment, and the STRING type by default
    - An anchor without a comment gets None
    - The JSON form of the set loads to the same config
    - A character outside the Basic Multilingual Plane, escaped as a surrogate pair, is decoded to
      that character in JSON and in YAML alike
    """
    config = await load_anchor_set(ANCHOR_SET)

    assert config.apply_to_all is False
    assert config.anchors[0] == Anchor(
        "luaL_checkversion_",
        AnchorType.STRING,
        "core and library have incompatible numeric types",
        "Checks that the Lua core and the C library were built with the same numeric types.",
    )
    assert config.anchors[3].value == "\n\t...\t(skipping %d levels)"
    assert config.anchors[-1] == Anchor("metatable_name_user", AnchorType.STRING, "__name", None)

    as_json = json.dumps(
        {
            "apply_to_all": True,
            "anchors": [
                {"name": a.name, "type": "STRING", "value": a.value, "comment": a.comment}
                for a in config.anchors
            ],
        }
    )
    assert parse_anchor_set(as_json) == ApplyAnchoredMarkupConfig(config.anchors, True)
    assert parse_anchor_set(json.dumps([{"name": "f", "value": "s"}])) == ApplyAnchoredMarkupConfig(
        [Anchor("f", AnchorType.STRING, "s")]
    )
    smiley = ApplyAnchoredMarkupConfig([Anchor("smile", AnchorType.STRING, "\U0001f600")])
    assert parse_anchor_set('[{"name": "smile", "value": "\\ud83d\\ude00"}]') == smiley
    assert parse_anchor_set('[{name: smile, value: "\\ud83d\\ude00"}]') == smiley


@pytest.mark.parametrize(
    "document, error",
    [
        ("", "must be a list of anchors or a mapping"),
        ("anchors: 5", "must be a list of anchors or a mapping"),
        ("{anchors: [], extra: 1}", "Unknown anchor set keys: extra"),
        ("{anchors: [], apply_to_all: maybe}", "apply_to_all must be true or false"),
        ("[5]", "must be a mapping"),
        ("[{name: f, value: s, string: s}]", "Unknown anchor keys: string"),
        ("[{name: f}]", "missing value"),
        ("[{name: f, value: s, type: SCALAR}]", "Unknown anchor type 'SCALAR'"),
        ("[{name: 5, value: s}]", "name of anchor .* must be a string"),
        ("[{name: f, value: s, comment: 5}]", "comment of anchor 'f' must be a string"),
        ("[{name: f, value: 5}]", "must be a non-empty string, not 5"),
        ("[{name: f, value: ''}]", "must be a non-empty string"),
        ("[{name: f, value: s}, {name: f, value: s}]", "anchor 'f' on 's' is given twice"),
        ("[{name: '', value: s}]", "non-empty name"),
        ("anchors: [", "must be JSON or YAML"),
        ('[{name: f, value: "\\ud83d"}]', "not valid Unicode"),
    ],
)
def test_invalid_anchor_set(document: str, error: str):
    """
    Test that invalid anchor sets are rejected with an explanation (REQ2.6).
    """
    with pytest.raises(ValueError, match=error):
        parse_anchor_set(document)


def test_anchor_config_rejects_unsupported_type():
    """
    Test that only string anchors are accepted (REQ2.6).
    """
    config = ApplyAnchoredMarkupConfig([Anchor("f", "STRING", "s")])  # type: ignore
    with pytest.raises(ValueError, match="Unsupported anchor type"):
        config.validate()


def test_anchor_config_rejects_invalid_unicode():
    """
    Test that an anchor whose string is not valid Unicode, so that no function can reference it,
    is rejected (REQ2.6).
    """
    config = ApplyAnchoredMarkupConfig([Anchor("f", AnchorType.STRING, "\ud83d")])
    with pytest.raises(ValueError, match="not valid Unicode"):
        config.validate()


async def test_apply_anchored_markup_validates_config(ofrak_context: OFRAKContext):
    """
    Test that ApplyAnchoredMarkupModifier rejects invalid anchors before resolving any (REQ2.6).
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    config = ApplyAnchoredMarkupConfig(
        [Anchor("f", AnchorType.STRING, "s"), Anchor("f", AnchorType.STRING, "s")]
    )
    with pytest.raises(ValueError, match="given twice"):
        await root.run(ApplyAnchoredMarkupModifier, config)


async def test_anchor_serialization(ofrak_context: OFRAKContext):
    """
    Test that anchors and their configs survive the PJSON serialization service (used e.g. by the
    OFRAK GUI server), keeping the type of an anchor's value (REQ2.6).

    This test verifies that:
    - A string-valued anchor keeps a string value
    - An integer-valued anchor keeps an integer value
    - An anchored markup config round-trips
    """
    serializer = await ofrak_context.injector.get_instance(PJSONSerializationService)
    for anchor in (Anchor("f", AnchorType.STRING, "1234"), Anchor("f", AnchorType.STRING, 1234)):
        restored = serializer.from_json(serializer.to_json(anchor, Anchor), Anchor)
        assert restored == anchor
        assert type(restored.value) is type(anchor.value)
    config = await load_anchor_set(ANCHOR_SET)
    assert (
        serializer.from_json(
            serializer.to_json(config, ApplyAnchoredMarkupConfig), ApplyAnchoredMarkupConfig
        )
        == config
    )
