"""
This module tests portable RE annotations: exporting a program's analyst markup to a portable,
git-diffable document, and importing it onto a build of the program with MarkupImportModifier.
The transfer between two different builds is measured by test_re_markup_experiment.

Requirements Mapping:
- REQ2.7
"""
import copy
import hashlib
import json
import os

import pytest

from ofrak import OFRAKContext
from ofrak.core import (
    AddCommentModifier,
    AddCommentModifierConfig,
    CommentsAttributes,
    ComplexBlock,
    MarkupImportConfig,
    MarkupImportModifier,
    MarkupImportReport,
    PortableFunctionMarkup,
    Program,
    ReferencedDataUnavailableError,
    RenameComplexBlockModifier,
    RenameComplexBlockModifierConfig,
    dumps_portable_markup,
    export_portable_markup,
    get_function_string_references,
    get_markup_serializer,
    load_portable_markup,
    loads_portable_markup,
    restrict_portable_markup,
    save_portable_markup,
)
from ofrak_type.range import Range
from pytest_ofrak import ASSETS_DIR as PYTEST_OFRAK_ASSETS_DIR
from .re_markup_experiment import (
    BUILD_A,
    BUILD_B,
    EXPORTED_MARKUP,
    analyze_build,
    get_complex_blocks,
    load_ground_truth,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data, usedforsecurity=False).hexdigest()


async def test_export_and_reimport_analyst_markup(ghidra_ofrak_context: OFRAKContext):
    """
    Test which markup of a real binary is exported, and that it is restored on a fresh analysis of
    the same binary (REQ2.7).

    This test verifies that:
    - Names applied with RenameComplexBlockModifier are exported, with the function's comments,
      sorted string references, code hash and size, in address order
    - A function with comments but no analyst name is exported without a name
    - Names applied without provenance, names that look like disassembler defaults, and names
      changed since an analyst set them are not exported
    - Every other function that references strings is exported without markup, as context
    - The program is labelled by its file name and identified by its SHA-256
    - Importing the export onto a fresh analysis restores exactly these names and comments,
      including the comment-only function, and touches no other function
    - A name an analyst already gave the function on the target is kept, and reported as a
      conflict
    """
    ground_truth = load_ground_truth(BUILD_A)
    vaddrs = {
        name: ground_truth.unique_vaddr(name)
        for name in (
            "luaL_checkversion_",
            "luaL_argerror",
            "luaL_typeerror",
            "luaL_traceback",
            "str_format",
            "os_date",
        )
    }
    root = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    complex_blocks = await get_complex_blocks(root)

    async def rename(function: str, name: str):
        await complex_blocks[vaddrs[function]].resource.run(
            RenameComplexBlockModifier, RenameComplexBlockModifierConfig(name)
        )

    async def comment(function: str, text: str, comment_range=None):
        await complex_blocks[vaddrs[function]].resource.run(
            AddCommentModifier, AddCommentModifierConfig((comment_range, text))
        )

    def rename_without_provenance(function: str, name: str):
        complex_block = complex_blocks[vaddrs[function]]
        complex_block.resource.add_view(
            ComplexBlock(complex_block.virtual_address, complex_block.size, name)
        )

    await rename("luaL_checkversion_", "check_lua_version")
    await comment("luaL_checkversion_", "Checks the numeric types")
    await comment("luaL_checkversion_", "Loads the version number", Range(0, 4))
    rename_without_provenance("luaL_argerror", "argument_error")
    await complex_blocks[vaddrs["luaL_argerror"]].resource.save()
    await comment("luaL_typeerror", "Raises a type error")
    await rename("luaL_traceback", "FUN_00408080")
    await rename("str_format", "format_string")
    rename_without_provenance("str_format", "formatter")
    await complex_blocks[vaddrs["str_format"]].resource.save()
    await rename("os_date", "os_date_implementation")

    program = await root.view_as(Program)
    markup = await export_portable_markup(program, BUILD_A.name)
    strings_by_function = await get_function_string_references(program)

    assert markup.program == BUILD_A.name
    assert markup.program_sha256 == _sha256(await root.get_data())
    marked_up = [record for record in markup.functions if record.has_markup()]
    assert [record.name for record in marked_up] == [
        None,
        "check_lua_version",
        "os_date_implementation",
    ]
    assert marked_up[0].comments == ["Raises a type error"]
    assert marked_up[1].comments == ["Checks the numeric types", "Loads the version number"]
    assert marked_up[2].comments == []
    for record, function in zip(marked_up, ("luaL_typeerror", "luaL_checkversion_", "os_date")):
        complex_block = complex_blocks[vaddrs[function]]
        assert record.string_refs == list(strings_by_function[vaddrs[function]])
        assert record.string_refs == sorted(record.string_refs)
        assert record.size == complex_block.size
        assert record.code_sha256 == _sha256(await complex_block.resource.get_data())
    exported_vaddrs = [
        vaddr
        for vaddr in sorted(complex_blocks)
        if vaddr in strings_by_function
        or vaddr in (vaddrs["luaL_checkversion_"], vaddrs["os_date"], vaddrs["luaL_typeerror"])
    ]
    assert [record.size for record in markup.functions] == [
        complex_blocks[vaddr].size for vaddr in exported_vaddrs
    ]

    fresh = await analyze_build(ghidra_ofrak_context, BUILD_A, live=False)
    fresh_blocks = await get_complex_blocks(fresh)
    # An analyst already named this function on the target
    await fresh_blocks[vaddrs["os_date"]].resource.run(
        RenameComplexBlockModifier, RenameComplexBlockModifierConfig("date_by_hand")
    )
    names_before = {vaddr: block.name for vaddr, block in (await get_complex_blocks(fresh)).items()}
    await fresh.run(MarkupImportModifier, MarkupImportConfig(markup))

    report = fresh.get_attributes(MarkupImportReport)
    assert [match.function_vaddrs for match in report.matched] == [
        (vaddrs["luaL_typeerror"],),
        (vaddrs["luaL_checkversion_"],),
    ]
    assert [(match.name, match.function_vaddrs) for match in report.conflicts] == [
        ("os_date_implementation", (vaddrs["os_date"],))
    ]
    assert report.ambiguous == report.unmatched == ()
    fresh_blocks = await get_complex_blocks(fresh)
    changed = {vaddr for vaddr, block in fresh_blocks.items() if block.name != names_before[vaddr]}
    assert changed == {vaddrs["luaL_checkversion_"]}
    assert fresh_blocks[vaddrs["luaL_checkversion_"]].name == "check_lua_version"
    assert fresh_blocks[vaddrs["os_date"]].name == "date_by_hand"
    for function, comments in (
        ("luaL_typeerror", ["Raises a type error"]),
        ("luaL_checkversion_", ["Checks the numeric types", "Loads the version number"]),
    ):
        resource = fresh_blocks[vaddrs[function]].resource
        assert resource.get_attributes(CommentsAttributes).comments == {None: comments}
    commented = [
        vaddr
        for vaddr, block in fresh_blocks.items()
        if block.resource.has_attributes(CommentsAttributes)
    ]
    assert sorted(commented) == sorted((vaddrs["luaL_typeerror"], vaddrs["luaL_checkversion_"]))


async def test_import_of_partial_markup_onto_another_build(ghidra_ofrak_context: OFRAKContext):
    """
    Test importing part of build A's committed markup onto build B, where some functions changed
    (REQ2.7).

    This test verifies that:
    - A record whose function is unchanged enough is applied to its counterpart in B
    - A record whose function was inlined away in B is not applied, even though the function of
      B that inlined it references the record's string: an unnamed function of A matches it as
      well, which the exported context records show
    - Byte-identical functions of A, which their order can only tell apart in the same build, are
      not applied to B
    """
    with open(EXPORTED_MARKUP, encoding="utf-8") as f:
        document = loads_portable_markup(
            f.read(), await get_markup_serializer(ghidra_ofrak_context)
        )
    ground_truth_b = load_ground_truth(BUILD_B)
    partial = restrict_portable_markup(
        document,
        lambda record: record.name
        in ("luaL_argerror", "checkupval", "genlink.cold", "propagatemark.cold"),
    )
    root = await analyze_build(ghidra_ofrak_context, BUILD_B, live=False)

    await root.run(MarkupImportModifier, MarkupImportConfig(partial))

    report = root.get_attributes(MarkupImportReport)
    assert [(match.name, match.function_vaddrs) for match in report.matched] == [
        ("luaL_argerror", (ground_truth_b.unique_vaddr("luaL_argerror"),))
    ]
    assert ground_truth_b.unique_vaddr("checkupval") is None
    assert sorted(match.name for match in report.ambiguous + report.unmatched) == [
        "checkupval",
        "genlink.cold",
        "propagatemark.cold",
    ]
    names = {block.name for block in (await get_complex_blocks(root)).values()}
    assert not names & {"checkupval", "genlink.cold", "propagatemark.cold"}


async def test_restrict_portable_markup(ofrak_context: OFRAKContext):
    """
    Test restricting the committed portable markup of a real program to some of its functions
    (REQ2.7).

    This test verifies that:
    - Only the kept functions keep their name and comments, in the same order
    - The other functions referencing strings stay as records without markup
    - A function referencing no string stays only if its code is identical to a kept function's
    """
    markup = await load_portable_markup(ofrak_context, EXPORTED_MARKUP)
    kept_names = ("luaL_argerror", "genlink.cold")

    restricted = restrict_portable_markup(markup, lambda record: record.name in kept_names)

    by_name = {record.name: record for record in markup.functions}
    assert [record for record in restricted.functions if record.has_markup()] == [
        record for record in markup.functions if record.name in kept_names
    ]
    twin_hash = by_name["genlink.cold"].code_sha256
    expected = [
        record
        for record in markup.functions
        if record.name in kept_names or record.string_refs or record.code_sha256 == twin_hash
    ]
    assert [(record.code_sha256, record.size) for record in restricted.functions] == [
        (record.code_sha256, record.size) for record in expected
    ]
    assert by_name["propagatemark.cold"].code_sha256 == twin_hash
    assert by_name["propagatemark.cold"].string_refs == []
    assert (restricted.program, restricted.program_sha256) == (
        markup.program,
        markup.program_sha256,
    )


async def test_portable_markup_document_round_trip(ofrak_context: OFRAKContext, tmp_path):
    """
    Test the committed portable markup of a real program through the SerializationService (REQ2.7).

    This test verifies that:
    - The document loads into PortableMarkup records with the expected fields
    - Serializing the loaded markup reproduces the committed document byte for byte, so
      re-exporting unchanged markup makes no diff
    - The markup survives being saved to and loaded from a file
    """
    with open(EXPORTED_MARKUP, encoding="utf-8") as f:
        document = f.read()
    serializer = await get_markup_serializer(ofrak_context)

    markup = loads_portable_markup(document, serializer)

    assert markup.program == BUILD_A.name
    assert len(markup.functions) > 500
    assert all(isinstance(record, PortableFunctionMarkup) for record in markup.functions)
    assert dumps_portable_markup(markup, serializer) == document
    path = str(tmp_path / "markup.json")
    await save_portable_markup(ofrak_context, markup, path)
    assert await load_portable_markup(ofrak_context, path) == markup


def _mutate(document: list, mutation: str) -> object:
    mutated = copy.deepcopy(document)
    record = mutated[1]["functions"][0][1]
    if mutation == "not a list":
        return mutated[1]
    if mutation == "foreign class":
        return ["ofrak.core.comments.CommentsAttributes", mutated[1]]
    if mutation == "functions not a list":
        mutated[1]["functions"] = "functions"
    elif mutation == "foreign function class":
        mutated[1]["functions"][0][0] = "ofrak.core.comments.CommentsAttributes"
    elif mutation == "program label":
        mutated[1]["program"] = 5
    elif mutation == "program sha256":
        mutated[1]["program_sha256"] = None
    elif mutation == "missing field":
        del record["size"]
    elif mutation == "prototype field":
        record["prototype"] = "int f(lua_State *L)"
    elif mutation == "name":
        record["name"] = 5
    elif mutation == "comments":
        record["comments"] = "comment"
    elif mutation == "string_refs":
        record["string_refs"] = [5]
    elif mutation == "code_sha256":
        record["code_sha256"] = 5
    elif mutation == "size":
        record["size"] = True
    return mutated


@pytest.mark.parametrize(
    "mutation, error",
    [
        ("not a list", "Expected a serialized PortableMarkup"),
        ("foreign class", "Expected a serialized PortableMarkup"),
        ("functions not a list", "functions must be of type list"),
        ("foreign function class", "Expected a serialized PortableFunctionMarkup"),
        ("program label", "program must be of type str"),
        ("program sha256", "program_sha256 must be of type str"),
        ("missing field", "Expected the fields .*, got name, comments, string_refs, code_sha256$"),
        ("prototype field", "Expected the fields .*, got .*, prototype$"),
        ("name", "name of a function must be a string or null"),
        ("comments", "comments must be of type list"),
        ("string_refs", "string_refs of .* must be a list of strings"),
        ("code_sha256", "code_sha256 must be of type str"),
        ("size", "size must be of type int, not True"),
    ],
)
async def test_invalid_portable_markup(ofrak_context: OFRAKContext, mutation: str, error: str):
    """
    Test that loading a document which is not valid portable markup fails before anything is
    deserialized (REQ2.7).

    This test verifies that:
    - Classes other than the markup's own are rejected
    - Missing and unexpected fields (like a function prototype, which OFRAK does not model) are
      rejected
    - Fields of the wrong type are rejected
    """
    with open(EXPORTED_MARKUP, encoding="utf-8") as f:
        document = json.load(f)
    serializer = await get_markup_serializer(ofrak_context)
    with pytest.raises(ValueError, match=error):
        loads_portable_markup(json.dumps(_mutate(document, mutation)), serializer)


@pytest.mark.parametrize(
    "similarity_threshold, max_size_ratio, error",
    [
        (-0.1, 4.0, "similarity_threshold must be in"),
        (1.0, 4.0, "similarity_threshold must be in"),
        (0.5, 0.5, "max_size_ratio must be at least 1"),
    ],
)
async def test_markup_import_config_validation(
    ofrak_context: OFRAKContext, similarity_threshold: float, max_size_ratio: float, error: str
):
    """
    Test that a markup import config with an out-of-range threshold is rejected (REQ2.7).
    """
    markup = await load_portable_markup(ofrak_context, EXPORTED_MARKUP)
    with pytest.raises(ValueError, match=error):
        MarkupImportConfig(markup, similarity_threshold, max_size_ratio)


async def test_portable_markup_without_data_references(ofrak_context: OFRAKContext):
    """
    Test that exporting and importing portable markup fail loudly when no backend provides data
    cross-references (REQ2.7).
    """
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(PYTEST_OFRAK_ASSETS_DIR, "hello.out")
    )
    await root.unpack()
    markup = await load_portable_markup(ofrak_context, EXPORTED_MARKUP)
    with pytest.raises(ReferencedDataUnavailableError):
        await root.run(MarkupImportModifier, MarkupImportConfig(markup))
    with pytest.raises(ReferencedDataUnavailableError):
        await export_portable_markup(await root.view_as(Program), "hello.out")
