"""
Portable RE annotations: export a program's analyst markup (function names and comments) to a
document that identifies each function without its address, and import that document onto a
different build of the program, where the functions have moved.
"""
import dataclasses
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import orjson

from ofrak.component.modifier import Modifier
from ofrak.core.anchored_markup import (
    apply_function_markup,
    get_analyst_name,
    get_complex_blocks_by_vaddr,
)
from ofrak.core.comments import CommentsAttributes
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.program import Program
from ofrak.core.referenced_strings import get_function_string_references
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.service.serialization.pjson import PJSONSerializationService
from ofrak.service.serialization.service_i import SerializationServiceInterface

if TYPE_CHECKING:  # pragma: no cover
    # Imported for type checking only: ofrak.ofrak_context imports ofrak.core
    from ofrak.ofrak_context import OFRAKContext

# Names disassembler backends give functions they know nothing about (Ghidra's FUN_00401000,
# IDA/Binary Ninja/angr's sub_401000, ...). They are never exported, even if one was applied
# explicitly.
_DISASSEMBLER_DEFAULT_NAME = re.compile(r"^(FUN|thunk_FUN|sub|j_sub|LAB)_[0-9a-fA-F]{4,}$")


@dataclass
class PortableFunctionMarkup:
    """
    The markup of one function, with fingerprints that identify the function independently of its
    address. A record with neither a name nor comments is the fingerprint of a function without
    markup that a function with markup could be mistaken for: importing it applies nothing, but
    keeps other records from being applied to its counterpart.

    :ivar name: The name an analyst gave the function, or None
    :ivar comments: The function's comments; comments on a byte range of the function are exported
    as comments on the whole function
    :ivar string_refs: The sorted texts of the strings the function references, the
    address-independent fingerprint used to find the function in another build
    :ivar code_sha256: SHA-256 of the function's bytes, which identifies the function exactly in
    the same build or in a build where its code did not change
    :ivar size: The function's size in bytes, used to rule out implausible matches
    """

    name: Optional[str]
    comments: List[str]
    string_refs: List[str]
    code_sha256: str
    size: int

    def has_markup(self) -> bool:
        """
        :return: Whether the record has a name or comments to apply
        """
        return self.name is not None or bool(self.comments)


@dataclass
class PortableMarkup:
    """
    A portable, git-diffable record of a program's analyst markup.

    :ivar program: A label for the program the markup was exported from
    :ivar program_sha256: SHA-256 of that program, which recognizes it as the import target
    :ivar functions: A record for each analyst-named or commented function, and for each function
    without markup that one of them could be mistaken for (see
    [PortableFunctionMarkup][ofrak.core.portable_markup.PortableFunctionMarkup]), ordered by the
    function's address in that program
    """

    program: str
    program_sha256: str
    functions: List[PortableFunctionMarkup]


@dataclass(frozen=True)
class MarkupMatch:
    """
    How one record of a [PortableMarkup][ofrak.core.portable_markup.PortableMarkup] was resolved.

    :ivar record_index: The record's index in `PortableMarkup.functions`
    :ivar name: The record's name
    :ivar function_vaddrs: The function the record matched (if matched, or in conflict), the
    candidate functions it could not choose between (if ambiguous), or nothing (if unmatched)
    :ivar similarity: The similarity of the best candidate, from 0 to 1
    """

    record_index: int
    name: Optional[str]
    function_vaddrs: Tuple[int, ...]
    similarity: float


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class MarkupImportReport(ResourceAttributes):
    """
    The outcome of the last [MarkupImportModifier][ofrak.core.portable_markup.MarkupImportModifier]
    run on a program, for each record with markup. Unmatched and ambiguous records are the
    functions that changed or disappeared in this build, as far as their fingerprints can tell.

    :ivar matched: Records that were applied, each to exactly one function
    :ivar ambiguous: Records that were not applied because several functions match them equally
    well, or because the function they match best matches another record (or a function without
    markup of the exported program) at least as well
    :ivar unmatched: Records that were not applied because no function matches them well enough
    :ivar conflicts: Records that were not applied because the function they match already has a
    different name given by an analyst
    """

    matched: Tuple[MarkupMatch, ...]
    ambiguous: Tuple[MarkupMatch, ...]
    unmatched: Tuple[MarkupMatch, ...]
    conflicts: Tuple[MarkupMatch, ...] = ()


@dataclass
class MarkupImportConfig(ComponentConfig):
    """
    :ivar markup: The markup to import
    :ivar similarity_threshold: The Jaccard similarity between a record's `string_refs` and a
    function's referenced strings must be greater than this for the function to be a candidate
    (default: more than half of the strings of both in common)
    :ivar max_size_ratio: Candidates whose size differs from the record's by more than this factor
    are rejected

    Constructing the config raises a `ValueError` if `similarity_threshold` is not in [0, 1) or
    `max_size_ratio` is less than 1.
    """

    markup: PortableMarkup
    similarity_threshold: float = 0.5
    max_size_ratio: float = 4.0

    def __post_init__(self):
        if not 0.0 <= self.similarity_threshold < 1.0:
            raise ValueError(
                f"similarity_threshold must be in [0, 1), not {self.similarity_threshold}"
            )
        if self.max_size_ratio < 1.0:
            raise ValueError(f"max_size_ratio must be at least 1, not {self.max_size_ratio}")


@dataclass(frozen=True)
class MarkupTarget:
    """
    A function of the program markup is imported onto, as seen by the matcher.

    :ivar vaddr: The function's virtual address
    :ivar size: The function's size in bytes
    :ivar code_sha256: SHA-256 of the function's bytes
    :ivar string_refs: The texts of the strings the function references
    """

    vaddr: int
    size: int
    code_sha256: str
    string_refs: FrozenSet[str]


class MarkupImportModifier(Modifier[MarkupImportConfig]):
    """
    Applies markup exported from another build of a program (see
    [export_portable_markup][ofrak.core.portable_markup.export_portable_markup]) to this build, by
    finding each recorded function by its fingerprint instead of its address, as
    [match_portable_markup][ofrak.core.portable_markup.match_portable_markup] describes: a record
    is applied to a function whose code and strings are identical, or else to the function whose
    referenced strings overlap the record's `string_refs` the most (Jaccard similarity), provided
    that the similarity is above `similarity_threshold`, the sizes are plausible, and no other
    function or record is as good a match. A record without such a match is reported as
    ambiguous or unmatched, and one whose function already has a different name from an analyst
    as a conflict: records are never force-applied. The names and comments are applied as in
    [ApplyAnchoredMarkupModifier][ofrak.core.anchored_markup.ApplyAnchoredMarkupModifier],
    and the outcome is recorded on the program as a
    [MarkupImportReport][ofrak.core.portable_markup.MarkupImportReport].

    Requires function→string references, derived from the data cross-references that only the
    Ghidra and Binary Ninja backends provide; raises
    [ReferencedDataUnavailableError][ofrak.core.referenced_strings.ReferencedDataUnavailableError]
    with any other backend.
    """

    targets = (Program,)

    async def modify(self, resource: Resource, config: MarkupImportConfig) -> None:
        program = await resource.view_as(Program)
        records = config.markup.functions
        matched, ambiguous, unmatched = match_portable_markup(
            records,
            await get_markup_targets(program),
            config.similarity_threshold,
            config.max_size_ratio,
            same_build=_sha256(await resource.get_data()) == config.markup.program_sha256,
        )
        complex_blocks = await get_complex_blocks_by_vaddr(program)
        applied: List[MarkupMatch] = []
        conflicts: List[MarkupMatch] = []
        for match in matched:
            record = records[match.record_index]
            if not record.has_markup():
                continue
            complex_block = complex_blocks[match.function_vaddrs[0]]
            if await apply_function_markup(complex_block, record.name, record.comments):
                applied.append(match)
            else:
                conflicts.append(match)
        resource.add_attributes(
            MarkupImportReport(
                matched=tuple(applied),
                ambiguous=tuple(m for m in ambiguous if records[m.record_index].has_markup()),
                unmatched=tuple(m for m in unmatched if records[m.record_index].has_markup()),
                conflicts=tuple(conflicts),
            )
        )


async def export_portable_markup(program: Program, label: str) -> PortableMarkup:
    """
    Export the analyst markup of a program: every function that was named by an analyst (see
    [AnalystNameAttributes][ofrak.core.complex_block.AnalystNameAttributes]) or has comments.
    Names that a disassembler assigned are not exported. The fingerprints of the functions without
    markup that reference strings, or whose code is identical to that of a function with markup,
    are exported too, so that the import can check that a function with markup is the best match
    of its counterpart among all the functions of this program, not only among those with markup.
    This is a helper rather than an analyzer, since its product is a document for other builds,
    not an attribute of this one.

    :param program: The program to export the markup of
    :param label: A name for the program in the document, such as its file name

    :raises ReferencedDataUnavailableError: if no backend can provide data cross-references

    :return: The program's portable markup
    """
    targets = await get_markup_targets(program)
    complex_blocks = await get_complex_blocks_by_vaddr(program)
    records = [
        PortableFunctionMarkup(
            name=_get_exported_name(complex_blocks[target.vaddr]),
            comments=_get_comments(complex_blocks[target.vaddr].resource),
            string_refs=sorted(target.string_refs),
            code_sha256=target.code_sha256,
            size=target.size,
        )
        for target in targets
    ]
    return PortableMarkup(
        program=label,
        program_sha256=_sha256(await program.resource.get_data()),
        functions=_select_records(records),
    )


def restrict_portable_markup(
    markup: PortableMarkup, keep: Callable[[PortableFunctionMarkup], bool]
) -> PortableMarkup:
    """
    Keep the markup of some functions only, as if the others had none, for instance to share part
    of a program's markup: the records of the other functions lose their name and comments, and
    are removed unless a function that keeps its markup could be mistaken for them, exactly as
    [export_portable_markup][ofrak.core.portable_markup.export_portable_markup] would have
    exported the program with only that markup.

    :param markup: The markup to restrict
    :param keep: Whether to keep the markup of a record

    :return: The restricted markup
    """
    records = [
        record if keep(record) else dataclasses.replace(record, name=None, comments=[])
        for record in markup.functions
    ]
    return PortableMarkup(markup.program, markup.program_sha256, _select_records(records))


def _select_records(records: Sequence[PortableFunctionMarkup]) -> List[PortableFunctionMarkup]:
    """
    :return: The records with markup, and those without markup that one of them could be mistaken
    for: the records of functions that reference strings, or whose code is identical to that of a
    record with markup
    """
    marked_up_code = {record.code_sha256 for record in records if record.has_markup()}
    return [
        record
        for record in records
        if record.has_markup() or record.string_refs or record.code_sha256 in marked_up_code
    ]


async def get_markup_targets(program: Program) -> List[MarkupTarget]:
    """
    Get the fingerprints of every function of a program.

    :param program: The program

    :raises ReferencedDataUnavailableError: if no backend can provide data cross-references

    :return: One target per complex block, ordered by address
    """
    string_refs = await get_function_string_references(program)
    complex_blocks = await get_complex_blocks_by_vaddr(program)
    return [
        MarkupTarget(
            vaddr=vaddr,
            size=complex_blocks[vaddr].size,
            code_sha256=_sha256(await complex_blocks[vaddr].resource.get_data()),
            string_refs=frozenset(string_refs.get(vaddr, ())),
        )
        for vaddr in sorted(complex_blocks)
    ]


def match_portable_markup(
    records: Sequence[PortableFunctionMarkup],
    targets: Sequence[MarkupTarget],
    similarity_threshold: float = 0.5,
    max_size_ratio: float = 4.0,
    same_build: bool = False,
) -> Tuple[Tuple[MarkupMatch, ...], Tuple[MarkupMatch, ...], Tuple[MarkupMatch, ...]]:
    """
    Decide which function each record belongs to. Records without markup take part like the
    others, so that a function with markup is only matched if it is the best match among all the
    functions of the exported program.

    1. Exact identity: a record and a function with the same `code_sha256`, and the same strings
       (identical code can reference different data in another build), match with similarity 1
       if they are the only ones with that code. Byte-identical functions of the same build are
       paired in address order.
    2. String fingerprint: every other record with `string_refs` is compared to each function not
       matched by identity whose size is within `max_size_ratio` of the record's, by the Jaccard
       similarity of their string sets. The record matches its best function if the similarity
       is greater than `similarity_threshold`, no other function is as similar to the record, and
       no other record is as similar to the function (mutual best match). Otherwise the record is
       ambiguous.

    Records with no candidate above the threshold are unmatched, including records without
    strings and without an identical function.

    :param records: The records of the exported program, in address order
    :param targets: The functions of the program to import onto
    :param similarity_threshold: The similarity of a match must be greater than this
    :param max_size_ratio: A record and a function whose sizes differ by more than this factor do
    not match
    :param same_build: Whether `targets` are the functions of the very program the records were
    exported from, so that byte-identical functions are in the same order

    :return: The matched, ambiguous and unmatched records
    """
    matched: Dict[int, MarkupMatch] = dict()
    ambiguous: Dict[int, MarkupMatch] = dict()
    unmatched: Dict[int, MarkupMatch] = dict()

    targets_by_hash: Dict[str, List[MarkupTarget]] = defaultdict(list)
    for target in sorted(targets, key=lambda t: t.vaddr):
        targets_by_hash[target.code_sha256].append(target)
    records_by_hash: Dict[str, List[int]] = defaultdict(list)
    for record_index, record in enumerate(records):
        records_by_hash[record.code_sha256].append(record_index)
    taken: Set[int] = set()
    for code_sha256, record_indices in records_by_hash.items():
        twins = targets_by_hash.get(code_sha256, [])
        pairs = list(zip(record_indices, twins))
        if (
            len(twins) == len(record_indices)
            and (len(twins) == 1 or same_build)
            and all(frozenset(records[i].string_refs) == t.string_refs for i, t in pairs)
        ):
            for record_index, target in pairs:
                matched[record_index] = MarkupMatch(
                    record_index, records[record_index].name, (target.vaddr,), 1.0
                )
                taken.add(target.vaddr)

    targets_by_string: Dict[str, List[MarkupTarget]] = defaultdict(list)
    for target in targets:
        if target.vaddr not in taken:
            for text in target.string_refs:
                targets_by_string[text].append(target)
    scores: Dict[int, Dict[int, float]] = dict()
    scores_by_target: Dict[int, List[Tuple[int, float]]] = defaultdict(list)
    for record_index, record in enumerate(records):
        if record_index in matched:
            continue
        record_strings = frozenset(record.string_refs)
        record_scores: Dict[int, float] = dict()
        for text in record_strings:
            for target in targets_by_string.get(text, ()):
                if target.vaddr not in record_scores and _plausible_size(
                    record.size, target.size, max_size_ratio
                ):
                    record_scores[target.vaddr] = _jaccard(record_strings, target.string_refs)
        scores[record_index] = record_scores
        for vaddr, score in record_scores.items():
            scores_by_target[vaddr].append((record_index, score))

    for record_index, record_scores in scores.items():
        name = records[record_index].name
        best_score = max(record_scores.values(), default=0.0)
        if best_score <= similarity_threshold:
            unmatched[record_index] = MarkupMatch(record_index, name, (), best_score)
            continue
        best = tuple(sorted(vaddr for vaddr, score in record_scores.items() if score == best_score))
        match = MarkupMatch(record_index, name, best, best_score)
        rival_records = [
            other
            for other, score in scores_by_target[best[0]]
            if other != record_index and score >= best_score
        ]
        if len(best) > 1 or rival_records:
            ambiguous[record_index] = match
        else:
            matched[record_index] = match

    return (
        tuple(matched[i] for i in sorted(matched)),
        tuple(ambiguous[i] for i in sorted(ambiguous)),
        tuple(unmatched[i] for i in sorted(unmatched)),
    )


def dumps_portable_markup(markup: PortableMarkup, serializer: SerializationServiceInterface) -> str:
    """
    Serialize markup to indented JSON, one value per line so that changes to the markup make small
    `git diff`s.

    :param markup: The markup to serialize
    :param serializer: The PJSON serialization service, e.g. from
    [get_markup_serializer][ofrak.core.portable_markup.get_markup_serializer]

    :return: The JSON document
    """
    pjson = serializer.to_pjson(markup, PortableMarkup)
    return orjson.dumps(pjson, option=orjson.OPT_INDENT_2).decode("utf-8") + "\n"


def loads_portable_markup(text: str, serializer: SerializationServiceInterface) -> PortableMarkup:
    """
    Deserialize markup written by
    [dumps_portable_markup][ofrak.core.portable_markup.dumps_portable_markup].
    The whole document is validated before it is deserialized, so a document cannot make the
    serializer instantiate classes other than the markup's own, or produce fields of other types.

    :param text: The JSON document
    :param serializer: The PJSON serialization service, e.g. from
    [get_markup_serializer][ofrak.core.portable_markup.get_markup_serializer]

    :raises ValueError: if the document is not portable markup

    :return: The markup
    """
    pjson = orjson.loads(text)
    _check_fields(
        _get_class_fields(pjson, PortableMarkup),
        {"program": str, "program_sha256": str, "functions": list},
    )
    for function in pjson[1]["functions"]:
        _check_record(_get_class_fields(function, PortableFunctionMarkup))
    return serializer.from_pjson(pjson, PortableMarkup)


async def get_markup_serializer(ofrak_context: "OFRAKContext") -> SerializationServiceInterface:
    """
    :param ofrak_context: The OFRAK context

    :return: The serialization service portable markup is written with
    """
    return await ofrak_context.injector.get_instance(PJSONSerializationService)


async def save_portable_markup(ofrak_context: "OFRAKContext", markup: PortableMarkup, path: str):
    """
    Write markup to a UTF-8 JSON file, as by
    [dumps_portable_markup][ofrak.core.portable_markup.dumps_portable_markup].

    :param ofrak_context: The OFRAK context, for its serialization service
    :param markup: The markup to write
    :param path: Path of the file to write
    """
    text = dumps_portable_markup(markup, await get_markup_serializer(ofrak_context))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


async def load_portable_markup(ofrak_context: "OFRAKContext", path: str) -> PortableMarkup:
    """
    Read markup from a UTF-8 JSON file, as by
    [loads_portable_markup][ofrak.core.portable_markup.loads_portable_markup].

    :param ofrak_context: The OFRAK context, for its serialization service
    :param path: Path of the file to read

    :raises ValueError: if the file is not portable markup

    :return: The markup
    """
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return loads_portable_markup(text, await get_markup_serializer(ofrak_context))


def _get_exported_name(complex_block: ComplexBlock) -> Optional[str]:
    name = get_analyst_name(complex_block)
    if name is None or _DISASSEMBLER_DEFAULT_NAME.match(name):
        return None
    return name


def _get_comments(resource: Resource) -> List[str]:
    if not resource.has_attributes(CommentsAttributes):
        return []
    comments_by_range = resource.get_attributes(CommentsAttributes).comments
    ordered_ranges = sorted(
        comments_by_range, key=lambda r: (-1, -1) if r is None else (r.start, r.end)
    )
    comments: List[str] = []
    for comment_range in ordered_ranges:
        for comment in comments_by_range[comment_range]:
            if comment not in comments:
                comments.append(comment)
    return comments


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data, usedforsecurity=False).hexdigest()


def _jaccard(a: FrozenSet[str], b: FrozenSet[str]) -> float:
    return len(a & b) / len(a | b)


def _plausible_size(record_size: int, target_size: int, max_size_ratio: float) -> bool:
    smaller, larger = sorted((max(record_size, 1), max(target_size, 1)))
    return larger <= smaller * max_size_ratio


def _get_class_fields(pjson: Any, cls: type) -> Dict[str, Any]:
    """
    :return: The fields of a serialized instance of `cls`
    """
    if (
        not isinstance(pjson, list)
        or len(pjson) != 2
        or pjson[0] != f"{cls.__module__}.{cls.__name__}"
        or not isinstance(pjson[1], dict)
    ):
        raise ValueError(f"Expected a serialized {cls.__name__}, got {str(pjson)[:100]}")
    return pjson[1]


def _check_fields(fields: Dict[str, Any], field_types: Dict[str, type]):
    if set(fields) != set(field_types):
        raise ValueError(
            f"Expected the fields {', '.join(field_types)}, got {', '.join(map(str, fields))}"
        )
    for field_name, field_type in field_types.items():
        value = fields[field_name]
        # bool is an int, but not a valid size
        if not isinstance(value, field_type) or (field_type is int and isinstance(value, bool)):
            raise ValueError(f"{field_name} must be of type {field_type.__name__}, not {value!r}")


def _check_record(fields: Dict[str, Any]):
    name = fields.get("name")
    if name is not None and not isinstance(name, str):
        raise ValueError(f"The name of a function must be a string or null, not {name!r}")
    _check_fields(
        fields,
        {
            "name": type(name),
            "comments": list,
            "string_refs": list,
            "code_sha256": str,
            "size": int,
        },
    )
    for field_name in ("comments", "string_refs"):
        if not all(isinstance(value, str) for value in fields[field_name]):
            raise ValueError(f"{field_name} of {name!r} must be a list of strings")
