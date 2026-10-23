"""
Experiment harness for anchor-based markup and portable RE annotations.

It measures how much reverse-engineering markup (function names and comments) made on build A of a
program ends up on the right functions of build B, the same source built by a different compiler
version: first with what OFRAK already offers (the baseline), then with the anchor-based markup
(#1) and portable markup (#2) components (the feature). The binaries are the committed pair in
`assets/re_markup` (see its README). The experiment runs on the stripped builds and takes its
ground truth from the symbol tables of the unstripped ones.

Measurements:

- `dataset`: the pair is checked to be a true A/B pair before anything else runs.
- `same_binary_survival` (the control, not the feature's value): A's markup after a full
  serialize→restore of the resource service, and after replaying an OfrakProject script on a fresh
  analysis of A.
- `cross_build_transfer` (baseline): A's markup re-applied to B by address, through the same
  OfrakProject script, and through a symbol table export (function names and entry addresses)
  re-imported into Ghidra's analysis of B by Ghidra's own ImportSymbolsScript.
- `feature`: #1 anchors derived from A's markup and #2 portable markup exported from A, applied to
  B; #2 when only part of A's functions are named; and the portable markup round trip onto a fresh
  analysis of A.

The baseline only uses what OFRAK offered before these components, so that it can also run on the
OFRAK before them, as the committed baseline report did (see the README).

The Ghidra backend analyzes the binaries, either live or (by default) by loading the committed
captures of its analysis, which makes the results deterministic. Run this module as a script to
regenerate the committed reports:

    python tests/components/re_markup_experiment.py baseline
    python tests/components/re_markup_experiment.py after
    python tests/components/re_markup_experiment.py variance --runs 5
"""
import argparse
import asyncio
import collections
import hashlib
import json
import logging
import os
import random
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Callable, Counter, Dict, Iterable, List, Optional, Set, Tuple

from elftools.elf.elffile import ELFFile

from ofrak import OFRAK, OFRAKContext, Resource, ResourceFilter
from ofrak.core import (
    AddCommentModifier,
    AddCommentModifierConfig,
    Addressable,
    CommentsAttributes,
    ComplexBlock,
    Program,
)
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.project.project import OfrakProject
from ofrak.service.resource_service import ResourceService
from ofrak.service.serialization.pjson import PJSONSerializationService

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "re_markup")
BASELINE_REPORT = os.path.join(ASSETS_DIR, "baseline_report.json")
AFTER_REPORT = os.path.join(ASSETS_DIR, "after_report.json")
VARIANCE_REPORT = os.path.join(ASSETS_DIR, "variance_report.json")
COMPARISON = os.path.join(ASSETS_DIR, "comparison.md")
# The markup of build A exported as portable markup, as committed for review
EXPORTED_MARKUP = os.path.join(ASSETS_DIR, "lua-gcc11-O2.markup.json")
# The Ghidra script exporting an analyzed program as a Ghidra Zip File, as the captures were made
EXPORT_GZF_SCRIPT = "ExportGzf.java"
# The Ghidra version the committed captures were made with (see capture_ghidra_analysis.sh)
CAPTURE_GHIDRA_VERSION = "11.3.2"

# A true A/B pair: most functions are in both builds, almost none at the same address, and most
# strings are in both
MIN_SHARED_FUNCTION_FRACTION = 0.9
MAX_SAME_ADDRESS_FRACTION = 0.05
MIN_SHARED_STRING_FRACTION = 0.5

# Pass conditions for the cross-build KPIs of the feature, set from the measurements on the
# committed pair (see after_report.json):
# - At most 1 in 20 of the names a feature method puts on B may be wrong, also when the analyst
#   named only part of the functions.
PRECISION_TARGET = 0.95
# - The portable markup import must name at least 30% of the analyst's functions that exist in B.
#   About two thirds of the functions reference no string at all, and are only found again when
#   their code did not change, which bounds the recall.
RECALL_FLOOR = 0.30
# - Results may move by the variance band without being a regression (see `variance_band`).
PRIOR_VARIANCE_BAND = 0.02

# The simulated analyst writes anchors on up to this many of a function's strings
ANCHORS_PER_FUNCTION = 2
# Partial markup: random subsets of the analyst's functions, each this fraction of them
PARTIAL_MARKUP_SUBSETS = 100
PARTIAL_MARKUP_FRACTION = 0.1

FEATURE_METHODS = (
    "anchored_markup",
    "portable_import",
    "portable_import_partial",
    "portable_round_trip",
)

# GCC names specialized clones of a function (interprocedural scalar replacement, constant
# propagation, ...) after the function, with a suffix. A clone is the same source function, so the
# ground truth identifies it by the original name. Partial (.part.N) and cold (.cold) fragments
# are only pieces of a function, and keep their own identity.
_CLONE_SUFFIX = re.compile(r"\.(isra|constprop|lto_priv)\.\d+|\.localalias")


@dataclass(frozen=True)
class Build:
    """
    One build of the experiment's program.
    """

    name: str

    @property
    def path(self) -> str:
        """The stripped binary the experiment analyzes"""
        return os.path.join(ASSETS_DIR, self.name)

    @property
    def unstripped_path(self) -> str:
        """The same binary with its symbol table, for the ground truth"""
        return os.path.join(ASSETS_DIR, f"{self.name}.unstripped")

    @property
    def capture_path(self) -> str:
        """Ghidra's analysis of the stripped binary, as a Ghidra Zip File"""
        return os.path.join(ASSETS_DIR, f"{self.name}.gzf")


BUILD_A = Build("lua-gcc11-O2")
BUILD_B = Build("lua-gcc15-O2")


@dataclass
class GroundTruth:
    """
    The real identity of a build's functions, from its symbol table.

    :ivar identities: The function identity at each function entry address
    :ivar counts: How many functions have each identity
    """

    identities: Dict[int, str]
    counts: Counter[str]

    def unique_vaddr(self, identity: str) -> Optional[int]:
        """
        :return: The entry address of the only function with this identity, or None if there is
        no such function or there are several
        """
        if self.counts.get(identity) != 1:
            return None
        return next(vaddr for vaddr, name in self.identities.items() if name == identity)


@dataclass(frozen=True)
class MarkupRecord:
    """
    The markup an analyst made on one function of build A.
    """

    vaddr: int
    name: str
    comment: str


# The name and whole-function comments of each function of a build, by address
FunctionState = Dict[int, Tuple[str, Tuple[str, ...]]]


def load_ground_truth(build: Build) -> GroundTruth:
    """
    Read the function identities of a build from its unstripped binary: every defined function
    symbol, named without GCC clone suffixes; a local name defined at several addresses is
    qualified with its file name.
    """
    entries: List[Tuple[int, str, Optional[str]]] = []
    with open(build.unstripped_path, "rb") as f:
        current_file = None
        for symbol in ELFFile(f).get_section_by_name(".symtab").iter_symbols():
            symbol_type = symbol["st_info"]["type"]
            if symbol_type == "STT_FILE":
                current_file = symbol.name
            elif (
                symbol_type == "STT_FUNC"
                and symbol["st_shndx"] != "SHN_UNDEF"
                and symbol["st_value"] != 0
            ):
                is_local = symbol["st_info"]["bind"] == "STB_LOCAL"
                name = _CLONE_SUFFIX.sub("", symbol.name)
                entries.append((symbol["st_value"], name, current_file if is_local else None))
    # Aliases of one function (such as a clone's .localalias) are at the same address
    vaddrs_by_name: Dict[str, Set[int]] = collections.defaultdict(set)
    for vaddr, name, _ in entries:
        vaddrs_by_name[name].add(vaddr)
    identities: Dict[int, str] = dict()
    for vaddr, name, file in entries:
        unique = len(vaddrs_by_name[name]) == 1
        identities.setdefault(vaddr, name if unique else f"{name}@{file}")
    return GroundTruth(identities, collections.Counter(identities.values()))


def read_rodata_strings(build: Build) -> Set[str]:
    """
    :return: Every NUL-terminated string of four or more printable characters (the default of
    `strings(1)`, which leaves out fragments of pointers) in the build's .rodata section
    """
    with open(build.path, "rb") as f:
        data = ELFFile(f).get_section_by_name(".rodata").data()
    return {
        match.decode("ascii") for match in re.findall(rb"[\x09\x0a\x0d\x20-\x7e]{4,}(?=\x00)", data)
    }


def describe_pair(ground_truth_a: GroundTruth, ground_truth_b: GroundTruth) -> Dict[str, Any]:
    """
    Describe the A/B pair from the files alone (symbol tables and string literals).
    """
    shared = set(ground_truth_a.identities.values()) & set(ground_truth_b.identities.values())
    same_address = [
        name
        for name in shared
        if ground_truth_a.unique_vaddr(name) is not None
        and ground_truth_a.unique_vaddr(name) == ground_truth_b.unique_vaddr(name)
    ]
    strings_a, strings_b = read_rodata_strings(BUILD_A), read_rodata_strings(BUILD_B)
    return {
        "functions_a": len(ground_truth_a.identities),
        "functions_b": len(ground_truth_b.identities),
        "shared_function_identities": len(shared),
        "same_address_fraction": _ratio(len(same_address), len(shared)),
        "rodata_strings_a": len(strings_a),
        "rodata_strings_b": len(strings_b),
        "shared_string_fraction": _ratio(len(strings_a & strings_b), len(strings_a | strings_b)),
    }


def validate_pair(pair: Dict[str, Any]):
    """
    Check that the builds are a true A/B pair: the same functions, at different addresses, with
    the same strings, so that markup can only be carried across by something other than addresses.

    :raises ValueError: if they are not
    """
    problems = []
    smaller = min(pair["functions_a"], pair["functions_b"])
    if pair["shared_function_identities"] < MIN_SHARED_FUNCTION_FRACTION * smaller:
        problems.append(f"only {pair['shared_function_identities']} functions are in both")
    if pair["same_address_fraction"] > MAX_SAME_ADDRESS_FRACTION:
        problems.append(f"{pair['same_address_fraction']} of the functions did not move")
    if pair["shared_string_fraction"] < MIN_SHARED_STRING_FRACTION:
        problems.append(f"only {pair['shared_string_fraction']} of the strings are in both")
    if problems:
        raise ValueError(f"The builds are not a true A/B pair: {'; '.join(problems)}")


async def analyze_build(
    ofrak_context: OFRAKContext, build: Build, live: bool, analysis: Optional[str] = None
) -> Resource:
    """
    Create a resource for a stripped build and unpack it down to complex blocks with the Ghidra
    backend, which analyzes it from scratch if `live`, and otherwise loads the committed capture of
    its analysis. The backend serves one analysis at a time, so everything needed from the previous
    build's analysis must be done before calling this.

    :param analysis: A Ghidra Zip File to load instead (of the build's analysis)
    """
    from ofrak_ghidra.components.ghidra_analyzer import GhidraProjectAnalyzer, GhidraProjectConfig

    root = await ofrak_context.create_root_resource_from_file(build.path)
    await root.identify()
    if analysis is None and not live:
        analysis = build.capture_path
    if analysis is not None:
        await root.run(GhidraProjectAnalyzer, GhidraProjectConfig(analysis, None, False))
    await root.unpack()
    for code_region in await (await root.view_as(Program)).get_code_regions():
        await code_region.resource.unpack()
    return root


async def get_complex_blocks(root: Resource) -> Dict[int, ComplexBlock]:
    """
    :return: Every complex block under `root`, by virtual address
    """
    complex_blocks = await root.get_descendants_as_view(
        ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
    )
    return {complex_block.virtual_address: complex_block for complex_block in complex_blocks}


async def get_function_state(root: Resource) -> FunctionState:
    """
    :return: The name and whole-function comments of every complex block under `root`
    """
    state: FunctionState = dict()
    for vaddr, complex_block in (await get_complex_blocks(root)).items():
        comments: Tuple[str, ...] = ()
        if complex_block.resource.has_attributes(CommentsAttributes):
            comments_attributes = complex_block.resource.get_attributes(CommentsAttributes)
            comments = tuple(comments_attributes.comments.get(None, ()))
        state[vaddr] = (complex_block.name, comments)
    return state


def make_analyst_markup(
    ground_truth: GroundTruth, function_vaddrs: Iterable[int]
) -> List[MarkupRecord]:
    """
    The simulated analyst names every function of build A whose identity is known and unique, and
    comments it. The set is fixed before any method runs, so that no method picks the functions it
    is good at.
    """
    markup = []
    for vaddr in sorted(function_vaddrs):
        name = ground_truth.identities.get(vaddr)
        if name is not None and ground_truth.counts[name] == 1:
            comment = f"Analyst note on {name}: reverse engineered on {BUILD_A.name}"
            markup.append(MarkupRecord(vaddr, name, comment))
    return markup


def check_no_analyst_names(state_b: FunctionState, markup: List[MarkupRecord]):
    """
    Check that the backend's own names on B cannot be mistaken for transferred markup.

    :raises ValueError: if B already has some of the analyst's names
    """
    analyst_names = {record.name for record in markup}
    colliding = sorted(name for name, _ in state_b.values() if name in analyst_names)
    if colliding:
        raise ValueError(f"B already has analyst names before any transfer: {colliding}")


async def apply_markup_with_existing_apis(root: Resource, markup: List[MarkupRecord]):
    """
    Apply markup the way OFRAK allows without the new components: replace each complex block view
    with a renamed one (the documented write-back pattern), and add a comment.
    """
    complex_blocks = await get_complex_blocks(root)
    for record in markup:
        complex_block = complex_blocks[record.vaddr]
        complex_block.resource.add_view(
            ComplexBlock(complex_block.virtual_address, complex_block.size, record.name)
        )
        await complex_block.resource.save()
        await complex_block.resource.run(
            AddCommentModifier, AddCommentModifierConfig((None, record.comment))
        )


async def apply_markup_with_rename_modifier(root: Resource, markup: List[MarkupRecord]):
    """
    Apply markup with RenameComplexBlockModifier, which records that the names are an analyst's.
    """
    from ofrak.core import RenameComplexBlockModifier, RenameComplexBlockModifierConfig

    complex_blocks = await get_complex_blocks(root)
    for record in markup:
        resource = complex_blocks[record.vaddr].resource
        await resource.run(
            RenameComplexBlockModifier, RenameComplexBlockModifierConfig(record.name)
        )
        await resource.run(AddCommentModifier, AddCommentModifierConfig((None, record.comment)))


def score_survival(state: FunctionState, markup: List[MarkupRecord]) -> Dict[str, Any]:
    """
    Score markup restored onto the same build: each record must be back on the function at its
    original address with its comment, and no other function may carry one of the analyst's names.
    """
    names_by_vaddr = {record.vaddr: record.name for record in markup}
    names_restored = sum(1 for r in markup if state.get(r.vaddr, ("", ()))[0] == r.name)
    comments_restored = sum(1 for r in markup if r.comment in state.get(r.vaddr, ("", ()))[1])
    analyst_names = set(names_by_vaddr.values())
    misplaced = sum(
        1
        for vaddr, (name, _) in state.items()
        if name in analyst_names and names_by_vaddr.get(vaddr) != name
    )
    return {
        "records": len(markup),
        "names_restored": names_restored,
        "comments_restored": comments_restored,
        "misplaced": misplaced,
        "survival": _ratio(min(names_restored, comments_restored), len(markup)),
    }


def score_transfer(
    state: FunctionState,
    markup: List[MarkupRecord],
    ground_truth_b: GroundTruth,
    reported: Optional[Set[str]],
    attempted: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """
    Score markup carried onto build B.

    - `transfer_recall`: records whose name ended up on their function in B, over all records whose
      function exists in B (a denominator fixed by the ground truth, not by the method)
    - `transfer_precision`: functions of B named after themselves, over all functions of B that got
      one of the analyst's names
    - `divergence_flagged`: whether every record that the method attempted but did not carry onto
      its function (because the function is absent from B, or changed beyond what the method can
      recognize) is in the method's own report of what it did not apply, rather than mislabeling
      another function or going unreported

    :param reported: Names of the records the method itself reported as not applied, or None if
    the method reports nothing
    :param attempted: Names of the records the method was given (by default all of them); the
    others count in the recall's denominator, but not as divergent
    """
    analyst_names = {record.name for record in markup}
    applied = {vaddr: name for vaddr, (name, _) in state.items() if name in analyst_names}
    correct = {
        vaddr for vaddr, name in applied.items() if ground_truth_b.identities.get(vaddr) == name
    }
    mislabeled = {name for vaddr, name in applied.items() if vaddr not in correct}
    true_vaddrs = {record.name: ground_truth_b.unique_vaddr(record.name) for record in markup}
    present = [record for record in markup if true_vaddrs[record.name] is not None]
    absent = [record for record in markup if record.name not in ground_truth_b.counts]
    transferred = {record.name for record in present if true_vaddrs[record.name] in correct}
    comments_transferred = [
        record
        for record in present
        if record.comment in state.get(true_vaddrs[record.name], ("", ()))[1]  # type: ignore
    ]

    def is_flagged(name: str) -> bool:
        return reported is not None and name in reported and name not in mislabeled

    divergent = [
        record.name
        for record in markup
        if (attempted is None or record.name in attempted) and record.name not in transferred
    ]
    divergent_reported = [name for name in divergent if is_flagged(name)]
    divergent_mislabeled = sorted(name for name in divergent if name in mislabeled)
    return {
        "records": len(markup),
        "attempted": len(markup) if attempted is None else len(attempted),
        "with_true_counterpart": len(present),
        "absent_in_b": len(absent),
        "applied": len(applied),
        "correct": len(correct),
        "transferred": len(transferred),
        "comments_transferred": len(comments_transferred),
        "transfer_recall": _ratio(len(transferred), len(present)),
        "transfer_precision": _ratio(len(correct), len(applied)),
        "comment_recall": _ratio(len(comments_transferred), len(present)),
        "reports_unapplied": reported is not None,
        "divergent": len(divergent),
        "divergent_reported": len(divergent_reported),
        "divergent_mislabeled": divergent_mislabeled,
        "divergent_unreported": len(divergent)
        - len(divergent_reported)
        - len(divergent_mislabeled),
        "absent_reported": sum(1 for record in absent if is_flagged(record.name)),
        "absent_mislabeled": sorted(record.name for record in absent if record.name in mislabeled),
        "divergence_flagged": reported is not None and len(divergent_reported) == len(divergent),
    }


def project_script(markup: List[MarkupRecord], capture_path: Optional[str]) -> str:
    """
    An OfrakProject script that applies markup by function address, the way scripts recorded by the
    OFRAK GUI select resources (by `Addressable.VirtualAddress`). Unlike a recorded script, it
    skips functions it cannot find instead of stopping at the first one.

    :param capture_path: Ghidra analysis to load, or None to let Ghidra analyze the binary
    """
    records = "".join(f"    ({r.vaddr:#x}, {r.name!r}, {r.comment!r}),\n" for r in markup)
    if capture_path is None:
        load_analysis = ""
    else:
        load_analysis = (
            "    from ofrak_ghidra.components.ghidra_analyzer import (\n"
            "        GhidraProjectAnalyzer,\n"
            "        GhidraProjectConfig,\n"
            "    )\n\n"
            "    await root_resource.identify()\n"
            "    await root_resource.run(\n"
            f"        GhidraProjectAnalyzer, GhidraProjectConfig({capture_path!r}, None, False)\n"
            "    )\n"
        )
    return f"""from ofrak import OFRAKContext, Resource, ResourceFilter
from ofrak.core import AddCommentModifier, AddCommentModifierConfig, ComplexBlock, Program

MARKUP = [
{records}]


async def main(ofrak_context: OFRAKContext, root_resource: Resource):
{load_analysis}    await root_resource.unpack()
    for code_region in await (await root_resource.view_as(Program)).get_code_regions():
        await code_region.resource.unpack()
    complex_blocks = {{
        complex_block.virtual_address: complex_block
        for complex_block in await root_resource.get_descendants_as_view(
            ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
    }}
    for vaddr, name, comment in MARKUP:
        if vaddr not in complex_blocks:
            continue
        complex_block = complex_blocks[vaddr]
        complex_block.resource.add_view(
            ComplexBlock(complex_block.virtual_address, complex_block.size, name)
        )
        await complex_block.resource.save()
        await complex_block.resource.run(
            AddCommentModifier, AddCommentModifierConfig((None, comment))
        )
"""


def symbol_export(markup: List[MarkupRecord]) -> str:
    """
    Export A's function names as a symbol table, in the `name address f` format that Ghidra's
    ImportSymbolsScript reads.
    """
    return "".join(f"{record.name} {record.vaddr:#x} f\n" for record in markup)


async def import_symbols_with_ghidra(
    build: Build, symbols_path: str, live: bool, work_dir: str
) -> Tuple[str, int]:
    """
    Re-apply a symbol table export the way a disassembler user would: run Ghidra's own
    ImportSymbolsScript on the build's analysis (from scratch if `live`, otherwise the committed
    capture), which renames the function at each symbol's address, or tries to create one there if
    there is none. The result is saved as a new Ghidra Zip File for the OFRAK Ghidra backend to
    load.

    :return: The path of that Ghidra Zip File, and at how many addresses the script tried to
    create a function (it reports an attempt as created even when Ghidra could not create it)
    """
    from ofrak_ghidra.constants import GHIDRA_PATH

    import_dir = os.path.join(work_dir, f"symbol-import-{build.name}")
    os.makedirs(import_dir)
    output = os.path.join(import_dir, f"{build.name}.gzf")
    # Not named after analyzeHeadless: the Ghidra backend kills processes matching that name
    log_path = os.path.join(import_dir, "ghidra-headless.log")
    headless = os.path.join(GHIDRA_PATH, "support", "analyzeHeadless")
    project = [headless, import_dir, "symbols"]
    source = build.path if live else build.capture_path
    no_analysis = [] if live else ["-noanalysis"]
    # The program is only saved to the project after its post-scripts ran, and a program with
    # unsaved changes cannot be exported, so export it from a second, read-only invocation
    for arguments in (
        ["-import", source] + no_analysis + ["-postScript", "ImportSymbolsScript.py", symbols_path],
        ["-process", "-noanalysis", "-readOnly", "-scriptPath", ASSETS_DIR]
        + ["-postScript", EXPORT_GZF_SCRIPT, output],
    ):
        with open(log_path, "a") as log:
            process = await asyncio.create_subprocess_exec(
                *project, *arguments, stdout=log, stderr=subprocess.STDOUT
            )
            await process.wait()
    with open(log_path) as log:
        script_output = log.read()
    if not os.path.isfile(output):
        raise RuntimeError(f"Ghidra did not export the symbol import; see {log_path}")
    return output, len(re.findall(r"^Created function ", script_output, re.M))


def describe_symbol_import(
    before: FunctionState, after: FunctionState, creation_attempts: int
) -> Dict[str, int]:
    """
    :return: What the symbol import did to B's functions, from the functions themselves
    """
    return {
        "functions_renamed": sum(
            1 for vaddr, (name, _) in after.items() if vaddr in before and before[vaddr][0] != name
        ),
        "functions_created": len(set(after) - set(before)),
        "functions_removed": len(set(before) - set(after)),
        "creation_attempts": creation_attempts,
    }


async def derive_anchors(root: Resource, markup: List[MarkupRecord]) -> List[Any]:
    """
    Write the anchor set an analyst would for A's markup: for each named function, anchors on its
    `ANCHORS_PER_FUNCTION` longest strings that no other function of A references. Functions
    without such a string get no anchor.
    """
    from ofrak.core import Anchor, AnchorType, get_function_string_references

    strings_by_function = await get_function_string_references(await root.view_as(Program))
    reference_counts = collections.Counter(
        text for texts in strings_by_function.values() for text in texts
    )
    anchors = []
    for record in markup:
        unique_strings = sorted(
            (
                text
                for text in strings_by_function.get(record.vaddr, ())
                if reference_counts[text] == 1
            ),
            key=lambda text: (-len(text), text),
        )
        for text in unique_strings[:ANCHORS_PER_FUNCTION]:
            anchors.append(Anchor(record.name, AnchorType.STRING, text, record.comment))
    return anchors


async def measure_serialization_survival(
    ofrak_context: OFRAKContext,
    make_markup: Callable[[FunctionState], List[MarkupRecord]],
    live: bool,
) -> Tuple[Dict[str, Any], FunctionState, List[MarkupRecord]]:
    """
    Control: apply A's markup, serialize the resource service with the SerializationService,
    deserialize it, and look for the markup in the restored service.

    :return: The score, the state of A before the markup, and the markup
    """
    root = await analyze_build(ofrak_context, BUILD_A, live)
    state_a = await get_function_state(root)
    markup = make_markup(state_a)
    await apply_markup_with_existing_apis(root, markup)
    serializer = await ofrak_context.injector.get_instance(PJSONSerializationService)
    serialized = serializer.to_json(ofrak_context.resource_service, ResourceService)
    restored: ResourceService = serializer.from_json(serialized, ResourceService)
    restored_state: FunctionState = dict()
    for model in await restored.get_descendants_by_id(
        root.get_id(), r_filter=ResourceFilter.with_tags(ComplexBlock)
    ):
        vaddr = model.get_attributes(AttributesType[Addressable]).virtual_address  # type: ignore
        name = model.get_attributes(AttributesType[ComplexBlock]).name  # type: ignore
        comments_attributes = model.get_attributes(CommentsAttributes)
        comments = () if comments_attributes is None else comments_attributes.comments.get(None, ())
        restored_state[vaddr] = (name, tuple(comments))
    score = dict(score_survival(restored_state, markup), serialized_bytes=len(serialized))
    return score, state_a, markup


async def measure_project_replay(
    ofrak_context: OFRAKContext,
    markup: List[MarkupRecord],
    build: Build,
    live: bool,
    work_dir: str,
) -> FunctionState:
    """
    Save A's markup in an OfrakProject as a script, re-open the project from disk, and run the
    script on a fresh analysis of `build` with `OfrakProject.init_project_binary`.
    """
    project_dir = os.path.join(work_dir, f"project-{build.name}")
    project = OfrakProject.create("re-markup", project_dir)
    with open(build.path, "rb") as f:
        project.add_binary(build.name, f.read())
    script = project_script(markup, None if live else build.capture_path)
    project.add_script("apply_markup.py", script)
    project.binaries[build.name].init_script = "apply_markup.py"
    project.write_metadata_to_disk()

    reopened = OfrakProject.init_from_path(project_dir)
    root = await reopened.init_project_binary(build.name, ofrak_context)
    return await get_function_state(root)


async def run_baseline(ofrak_context: OFRAKContext, live: bool, work_dir: str) -> Dict[str, Any]:
    """
    Measure what OFRAK achieves without the new components.
    """
    ground_truth_a = load_ground_truth(BUILD_A)
    ground_truth_b = load_ground_truth(BUILD_B)
    pair = describe_pair(ground_truth_a, ground_truth_b)
    validate_pair(pair)
    serialization, state_a, markup = await measure_serialization_survival(
        ofrak_context, lambda state: make_analyst_markup(ground_truth_a, state.keys()), live
    )
    replay_a = await measure_project_replay(ofrak_context, markup, BUILD_A, live, work_dir)
    replay_b = await measure_project_replay(ofrak_context, markup, BUILD_B, live, work_dir)
    pristine_b = await get_function_state(await analyze_build(ofrak_context, BUILD_B, live))
    check_no_analyst_names(pristine_b, markup)
    symbols_path = os.path.join(work_dir, "symbols.txt")
    with open(symbols_path, "w") as f:
        f.write(symbol_export(markup))
    symbols_analysis, creation_attempts = await import_symbols_with_ghidra(
        BUILD_B, symbols_path, live, work_dir
    )
    symbols_b = await get_function_state(
        await analyze_build(ofrak_context, BUILD_B, live, symbols_analysis)
    )
    return {
        "dataset": dict(
            pair,
            functions_found_a=len(state_a),
            functions_found_b=len(pristine_b),
            analyst_named=len(markup),
        ),
        "same_binary_survival": {
            "serialize_restore": serialization,
            "ofrak_project_replay": score_survival(replay_a, markup),
        },
        "cross_build_transfer": {
            "address_keyed_reapply": score_transfer(replay_b, markup, ground_truth_b, None),
            "symbol_export_reapply": dict(
                score_transfer(symbols_b, markup, ground_truth_b, None),
                **describe_symbol_import(pristine_b, symbols_b, creation_attempts),
            ),
        },
    }


def measure_partial_markup(
    document: Any, targets_b: List[Any], markup: List[MarkupRecord], ground_truth_b: GroundTruth
) -> Dict[str, Any]:
    """
    Measure the portable markup import when the analyst named only part of A's functions: for
    each of `PARTIAL_MARKUP_SUBSETS` random subsets (fixed seeds) of `PARTIAL_MARKUP_FRACTION` of
    the analyst's functions, restrict A's exported markup to the subset, exactly as A would have
    been exported with only that markup, and match it onto B's functions as the import does.

    :param document: A's exported portable markup
    :param targets_b: The fingerprints of B's functions
    """
    from ofrak.core import match_portable_markup, restrict_portable_markup

    names = sorted(record.name for record in markup)
    true_vaddrs = {name: ground_truth_b.unique_vaddr(name) for name in names}
    subset_size = round(len(names) * PARTIAL_MARKUP_FRACTION)
    subsets = []
    for seed in range(PARTIAL_MARKUP_SUBSETS):
        subset = set(random.Random(seed).sample(names, subset_size))
        partial = restrict_portable_markup(document, lambda record: record.name in subset)
        matched, _, _ = match_portable_markup(partial.functions, targets_b)
        applied = {
            partial.functions[match.record_index].name: match.function_vaddrs[0]
            for match in matched
            if partial.functions[match.record_index].has_markup()
        }
        wrong = [name for name, vaddr in applied.items() if true_vaddrs[name] != vaddr]
        present = [name for name in subset if true_vaddrs[name] is not None]
        subsets.append(
            {
                "applied": len(applied),
                "wrong": len(wrong),
                "absent_mislabeled": sum(1 for name in wrong if true_vaddrs[name] is None),
                "recall": (len(applied) - len(wrong)) / len(present),
                "precision": None if not applied else (len(applied) - len(wrong)) / len(applied),
            }
        )
    precisions = [s["precision"] for s in subsets if s["precision"] is not None]
    recalls = [s["recall"] for s in subsets]
    return {
        "subsets": len(subsets),
        "records_per_subset": subset_size,
        "subsets_with_a_wrong_name": sum(1 for s in subsets if s["wrong"]),
        "wrong_names": sum(s["wrong"] for s in subsets),
        "absent_mislabeled": sum(s["absent_mislabeled"] for s in subsets),
        "precision_min": round(min(precisions), 4),
        "precision_mean": round(sum(precisions) / len(precisions), 4),
        "recall_min": round(min(recalls), 4),
        "recall_mean": round(sum(recalls) / len(recalls), 4),
    }


async def run_feature(
    ofrak_context: OFRAKContext,
    live: bool,
    work_dir: str,
    methods: Iterable[str] = FEATURE_METHODS,
) -> Dict[str, Any]:
    """
    Measure the anchor-based (#1) and portable (#2) markup components.
    """
    from ofrak.core import (
        AnchorResolutionReport,
        ApplyAnchoredMarkupConfig,
        ApplyAnchoredMarkupModifier,
        MarkupImportConfig,
        MarkupImportModifier,
        MarkupImportReport,
        dumps_portable_markup,
        export_portable_markup,
        get_markup_serializer,
        get_markup_targets,
        loads_portable_markup,
    )

    methods = set(methods)
    ground_truth_a = load_ground_truth(BUILD_A)
    ground_truth_b = load_ground_truth(BUILD_B)
    validate_pair(describe_pair(ground_truth_a, ground_truth_b))
    root_a = await analyze_build(ofrak_context, BUILD_A, live)
    markup = make_analyst_markup(ground_truth_a, (await get_function_state(root_a)).keys())
    await apply_markup_with_rename_modifier(root_a, markup)
    serializer = await get_markup_serializer(ofrak_context)
    exported = await export_portable_markup(await root_a.view_as(Program), BUILD_A.name)
    document = dumps_portable_markup(exported, serializer)
    with open(os.path.join(work_dir, "markup.json"), "w", encoding="utf-8") as f:
        f.write(document)
    anchors = await derive_anchors(root_a, markup)
    results: Dict[str, Any] = dict()

    if {"portable_import", "portable_import_partial"} & methods:
        root_b = await analyze_build(ofrak_context, BUILD_B, live)
        markup_document = loads_portable_markup(document, serializer)
        if "portable_import_partial" in methods:
            targets_b = await get_markup_targets(await root_b.view_as(Program))
            results["portable_import_partial"] = measure_partial_markup(
                markup_document, targets_b, markup, ground_truth_b
            )
        if "portable_import" in methods:
            await root_b.run(MarkupImportModifier, MarkupImportConfig(markup_document))
            report = root_b.get_attributes(MarkupImportReport)
            not_applied = {
                markup_document.functions[match.record_index].name
                for match in report.ambiguous + report.unmatched + report.conflicts
            }
            records = markup_document.functions
            results["portable_import"] = dict(
                score_transfer(
                    await get_function_state(root_b),
                    markup,
                    ground_truth_b,
                    {name for name in not_applied if name is not None},
                ),
                exported_records=sum(1 for record in records if record.has_markup()),
                exported_context_records=sum(1 for record in records if not record.has_markup()),
                exported_records_with_strings=sum(
                    1 for record in records if record.has_markup() and record.string_refs
                ),
                matched=len(report.matched),
                ambiguous=len(report.ambiguous),
                unmatched=len(report.unmatched),
                conflicts=len(report.conflicts),
            )

    if "anchored_markup" in methods:
        root_b = await analyze_build(ofrak_context, BUILD_B, live)
        await root_b.run(ApplyAnchoredMarkupModifier, ApplyAnchoredMarkupConfig(anchors))
        anchor_report = root_b.get_attributes(AnchorResolutionReport)
        anchored_names = {anchor.name for anchor in anchors}
        results["anchored_markup"] = dict(
            score_transfer(
                await get_function_state(root_b),
                markup,
                ground_truth_b,
                set(anchor_report.misses)
                | set(anchor_report.ambiguous)
                | set(anchor_report.conflicts),
                attempted=anchored_names,
            ),
            anchors=len(anchors),
            anchored_functions=len(anchored_names),
            hits=len(anchor_report.hits),
            misses=len(anchor_report.misses),
            ambiguous=len(anchor_report.ambiguous),
            conflicts=len(anchor_report.conflicts),
        )

    if "portable_round_trip" in methods:
        fresh_a = await analyze_build(ofrak_context, BUILD_A, live)
        markup_document = loads_portable_markup(document, serializer)
        await fresh_a.run(MarkupImportModifier, MarkupImportConfig(markup_document))
        results["portable_round_trip"] = score_survival(await get_function_state(fresh_a), markup)
    return results


async def run_after(ofrak_context: OFRAKContext, live: bool, work_dir: str) -> Dict[str, Any]:
    """
    Measure the feature on the pair, then re-run the baseline measurements (including the control)
    with the feature present.
    """
    feature = await run_feature(ofrak_context, live, work_dir)
    return dict(await run_baseline(ofrak_context, live, work_dir), feature=feature)


def describe_run(live: bool) -> Dict[str, Any]:
    """
    :return: What produced a report: the exact assets, the commits of the OFRAK that ran and of
    this harness, the Ghidra version, and the analysis source
    """
    import ofrak
    import ofrak_ghidra

    assets = dict()
    for build in (BUILD_A, BUILD_B):
        for path in (build.path, build.unstripped_path, build.capture_path):
            with open(path, "rb") as f:
                assets[os.path.basename(path)] = hashlib.sha256(
                    f.read(), usedforsecurity=False
                ).hexdigest()
    return {
        "assets": assets,
        "ofrak_commit": _git_commit([os.path.dirname(ofrak.__file__)]),
        "harness_commit": _git_commit(
            [os.path.abspath(__file__), os.path.dirname(ofrak_ghidra.__file__)]
        ),
        "ghidra_version": get_ghidra_version(),
        "analysis": "live Ghidra auto-analysis" if live else "committed Ghidra analysis captures",
    }


def get_ghidra_version() -> str:
    """
    :return: The version of the Ghidra installation the backend uses
    """
    from ofrak_ghidra.constants import GHIDRA_PATH

    with open(os.path.join(GHIDRA_PATH, "Ghidra", "application.properties")) as f:
        for line in f:
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    raise ValueError(f"No application.version in the Ghidra installation at {GHIDRA_PATH}")


def variance_band() -> float:
    """
    :return: How much a KPI may move without being a regression: twice the largest spread of any
    KPI between the live runs of variance_report.json, but at least `PRIOR_VARIANCE_BAND` (twice
    the ~1% run-to-run variance expected of Ghidra's auto-analysis, which analysis timeouts can
    cause on slower or busier machines than the one that made the report)
    """
    largest_spread = 0.0
    if os.path.exists(VARIANCE_REPORT):
        for spreads in read_json(VARIANCE_REPORT)["spread"].values():
            largest_spread = max([largest_spread, *spreads.values()])
    return max(PRIOR_VARIANCE_BAND, 2 * largest_spread)


def compare_reports(baseline: Dict[str, Any], after: Dict[str, Any]) -> str:
    """
    :return: A Markdown before/after comparison of the cross-build KPIs and the control
    """
    rows = []
    for label, method in (
        ("Address-keyed re-apply (OfrakProject script)", "address_keyed_reapply"),
        ("Symbol table re-imported by Ghidra's ImportSymbolsScript", "symbol_export_reapply"),
    ):
        rows.append((f"Baseline: {label}", baseline["cross_build_transfer"][method]))
    for label, method in (
        ("#1 Anchors derived from A", "anchored_markup"),
        ("#2 Portable markup import", "portable_import"),
    ):
        rows.append((f"Feature: {label}", after["feature"][method]))
    partial = after["feature"]["portable_import_partial"]
    lines = [
        "# Portable RE markup: before/after",
        "",
        f"Markup transferred from `{BUILD_A.name}` to `{BUILD_B.name}` "
        f"({after['dataset']['analyst_named']} analyst-named functions, "
        f"{after['cross_build_transfer']['address_keyed_reapply']['with_true_counterpart']} of "
        "them with a counterpart in B).",
        "",
        "| Method | transfer_recall | transfer_precision | comment_recall | divergence_flagged |",
        "|---|---|---|---|---|",
    ]
    for label, scores in rows:
        lines.append(
            f"| {label} | {_format(scores['transfer_recall'])} | "
            f"{_format(scores['transfer_precision'])} | {_format(scores['comment_recall'])} | "
            f"{'yes' if scores['divergence_flagged'] else 'no'} |"
        )
    lines += [
        "",
        f"#2 with partial markup ({partial['subsets']} random subsets of "
        f"{partial['records_per_subset']} of the analyst's functions): transfer_precision "
        f"{_format(partial['precision_min'])} at worst ({_format(partial['precision_mean'])} on "
        f"average), transfer_recall {_format(partial['recall_mean'])} on average; "
        f"{partial['subsets_with_a_wrong_name']} subsets put a name on a wrong function.",
        "",
        "Control (same binary, expected to be unchanged):",
        "",
        "| Measurement | before | after |",
        "|---|---|---|",
    ]
    for method in ("serialize_restore", "ofrak_project_replay"):
        lines.append(
            f"| {method} | {_format(baseline['same_binary_survival'][method]['survival'])} | "
            f"{_format(after['same_binary_survival'][method]['survival'])} |"
        )
    lines.append(
        f"| portable_round_trip (feature) | n/a | "
        f"{_format(after['feature']['portable_round_trip']['survival'])} |"
    )
    lines += ["", "Produced from:", ""]
    for report_name, report in (("before", baseline), ("after", after)):
        run = report["run"]
        lines.append(
            f"- {report_name}: OFRAK `{run['ofrak_commit']}` (harness `{run['harness_commit']}`), "
            f"Ghidra {run['ghidra_version']}, {run['analysis']}"
        )
    lines += ["", "Assets (SHA-256):", ""]
    lines += [f"- `{name}`: `{digest}`" for name, digest in sorted(after["run"]["assets"].items())]
    return "\n".join(lines) + "\n"


def summarize_kpis(baseline: Dict[str, Any], feature: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    :return: The KPIs of every method, as compared between variance runs
    """
    kpis = ("transfer_recall", "transfer_precision", "comment_recall")
    summary = {
        method: {kpi: baseline["cross_build_transfer"][method][kpi] for kpi in kpis}
        for method in ("address_keyed_reapply", "symbol_export_reapply")
    }
    for method in ("anchored_markup", "portable_import"):
        summary[method] = {kpi: feature[method][kpi] for kpi in kpis}
    summary["portable_import_partial"] = {
        kpi: feature["portable_import_partial"][kpi]
        for kpi in ("precision_min", "precision_mean", "recall_min", "recall_mean")
    }
    summary["portable_round_trip"] = {"survival": feature["portable_round_trip"]["survival"]}
    for method in ("serialize_restore", "ofrak_project_replay"):
        summary[method] = {"survival": baseline["same_binary_survival"][method]["survival"]}
    return summary


async def measure_variance(ofrak_context: OFRAKContext, runs: int, work_dir: str) -> Dict[str, Any]:
    """
    Run every measurement with live Ghidra analysis several times and report how much each KPI
    moves between runs.
    """
    results = []
    for run in range(runs):
        run_dir = os.path.join(work_dir, f"run-{run}")
        os.makedirs(run_dir)
        feature = await run_feature(ofrak_context, True, run_dir)
        baseline = await run_baseline(ofrak_context, True, run_dir)
        results.append(summarize_kpis(baseline, feature))
    spread = {
        method: {
            kpi: round(
                max(result[method][kpi] for result in results)
                - min(result[method][kpi] for result in results),
                4,
            )
            for kpi in kpis
        }
        for method, kpis in results[0].items()
    }
    return {"runs": results, "spread": spread}


def write_json(report: Dict[str, Any], path: str):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")


def read_json(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return None if denominator == 0 else round(numerator / denominator, 4)


def _format(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _git_commit(paths: List[str]) -> str:
    """
    :param paths: Files or directories of one git repository

    :return: The commit of the repository, with "-dirty" if some of `paths` have uncommitted
    changes
    """
    directory = paths[0] if os.path.isdir(paths[0]) else os.path.dirname(paths[0])

    def git(*arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments], cwd=directory, capture_output=True, text=True
        ).stdout.strip()

    dirty = git("status", "--porcelain", "--untracked-files=no", "--", *paths)
    return f"{git('rev-parse', 'HEAD')}{'-dirty' if dirty else ''}"


async def _main(ofrak_context: OFRAKContext, args: argparse.Namespace):
    # Before running: the commits must be those of the code that runs
    run = describe_run(args.live or args.command == "variance")
    with tempfile.TemporaryDirectory() as work_dir:
        if args.command == "baseline":
            report = await run_baseline(ofrak_context, args.live, work_dir)
            write_json(dict(report, run=run), BASELINE_REPORT)
        elif args.command == "after":
            report = dict(await run_after(ofrak_context, args.live, work_dir), run=run)
            write_json(report, AFTER_REPORT)
            with open(COMPARISON, "w") as f:
                f.write(compare_reports(read_json(BASELINE_REPORT), report))
            shutil.copyfile(os.path.join(work_dir, "markup.json"), EXPORTED_MARKUP)
        else:
            variance = await measure_variance(ofrak_context, args.runs, work_dir)
            write_json(dict(variance, run=run), VARIANCE_REPORT)


if __name__ == "__main__":
    import ofrak_ghidra

    parser = argparse.ArgumentParser(description="Regenerate the portable RE markup reports")
    parser.add_argument("command", choices=("baseline", "after", "variance"))
    parser.add_argument("--live", action="store_true", help="Analyze with Ghidra from scratch")
    parser.add_argument("--runs", type=int, default=5, help="Live runs for `variance`")
    ofrak = OFRAK(logging.WARNING)
    ofrak.discover(ofrak_ghidra)
    ofrak.run(_main, parser.parse_args())
