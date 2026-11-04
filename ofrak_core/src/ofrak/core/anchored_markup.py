"""
Anchor-based markup: name and comment functions by a stable property they reference, rather than
by address, so that one markup recipe can be re-applied to a different build of a program.
"""
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union, cast

import yaml

from ofrak.component.modifier import Modifier
from ofrak.core.comments import AddCommentModifier, AddCommentModifierConfig, CommentsAttributes
from ofrak.core.complex_block import (
    AnalystNameAttributes,
    ComplexBlock,
    RenameComplexBlockModifier,
    RenameComplexBlockModifierConfig,
)
from ofrak.core.program import Program
from ofrak.core.referenced_strings import get_function_string_references
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter


class AnchorType(Enum):
    """
    The kind of stable property an [Anchor][ofrak.core.anchored_markup.Anchor] uses to find its
    function.

    - `STRING`: the function references a string literal whose text is exactly the anchor's value
    """

    STRING = 0


@dataclass
class Anchor:
    """
    Markup to attach to a function, together with the stable property that identifies it.

    :ivar name: The name to give the function the anchor resolves to
    :ivar anchor_type: How `value` identifies the function
    :ivar value: For a `STRING` anchor, the exact text of a string the function references
    :ivar comment: An optional comment to add to the function
    """

    name: str
    anchor_type: AnchorType
    value: Union[str, int]
    comment: Optional[str] = None


@dataclass
class ApplyAnchoredMarkupConfig(ComponentConfig):
    """
    :ivar anchors: The anchors to resolve and apply. Several anchors with the same name identify
    one function together: it is the function that all of those which match anything reference
    :ivar apply_to_all: Apply an anchor to every function it matches, instead of reporting an
    anchor that matches more than one function as ambiguous and not applying it
    """

    anchors: List[Anchor]
    apply_to_all: bool = False

    def validate(self):
        """
        Check the anchors, as
        [ApplyAnchoredMarkupModifier][ofrak.core.anchored_markup.ApplyAnchoredMarkupModifier]
        does before applying them.

        :raises ValueError: if an anchor has no name, is not a `STRING` anchor with a non-empty
        string value of valid Unicode, or is given twice
        """
        anchors: Set[Tuple[str, str]] = set()
        for anchor in self.anchors:
            if not anchor.name:
                raise ValueError("Every anchor needs a non-empty name")
            if anchor.anchor_type is not AnchorType.STRING:
                raise ValueError(
                    f"Unsupported anchor type {anchor.anchor_type} for {anchor.name!r}"
                )
            if not isinstance(anchor.value, str) or not anchor.value:
                raise ValueError(
                    f"The value of STRING anchor {anchor.name!r} must be a non-empty string, "
                    f"not {anchor.value!r}"
                )
            try:
                anchor.value.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError(
                    f"The value of anchor {anchor.name!r} is not valid Unicode: {anchor.value!r}"
                )
            if (anchor.name, anchor.value) in anchors:
                raise ValueError(f"The anchor {anchor.name!r} on {anchor.value!r} is given twice")
            anchors.add((anchor.name, anchor.value))


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AnchorResolutionReport(ResourceAttributes):
    """
    The outcome of the last
    [ApplyAnchoredMarkupModifier][ofrak.core.anchored_markup.ApplyAnchoredMarkupModifier]
    run on a program, by anchor name. A miss or an ambiguous anchor is a cross-version signal in
    itself: the function changed, moved, or no longer references the anchor's string.

    :ivar hits: For each applied anchor, the virtual addresses of the functions it named
    :ivar misses: The anchors which matched no function
    :ivar ambiguous: For each anchor that was not applied because it matched several functions,
    because anchors with its name match different functions, or because an anchor with a different
    name resolved to the same function, the virtual addresses of the functions it matched
    :ivar conflicts: For each anchor that matched functions which already have a different name
    given by an analyst, the virtual addresses of those functions, which were left unchanged
    :ivar missing_strings: For each anchor name, the strings of its anchors that no function
    references: all of them for a miss, and otherwise those of the anchors that its other anchors
    made up for, which are a sign that the function changed too
    """

    hits: Dict[str, Tuple[int, ...]] = field(default_factory=dict)
    misses: Tuple[str, ...] = ()
    ambiguous: Dict[str, Tuple[int, ...]] = field(default_factory=dict)
    conflicts: Dict[str, Tuple[int, ...]] = field(default_factory=dict)
    missing_strings: Dict[str, Tuple[str, ...]] = field(default_factory=dict)


class ApplyAnchoredMarkupModifier(Modifier[ApplyAnchoredMarkupConfig]):
    """
    Names and comments functions found by an anchor (a string they reference) instead of by their
    address, so the same anchor set re-applies to another build or version of the program where
    the functions have moved. Each anchor resolves to the
    [complex blocks][ofrak.core.complex_block.ComplexBlock] that reference its string, and the
    anchors with the same name to the functions they all match (ignoring those that match
    nothing). A unique match is renamed with
    [RenameComplexBlockModifier][ofrak.core.complex_block.RenameComplexBlockModifier] and commented,
    unless an analyst already gave it a different name. Anchors matching no function are a miss;
    anchors matching several functions, or anchors with the same name matching different
    functions, or the same function as an anchor with another name, are ambiguous and are not
    applied (unless `apply_to_all` allows several matches). An anchor is thus only applied where it
    identifies one function; it can still name the wrong function if its string moved to another
    function in this build (for instance when the compiler inlined differently), which further
    anchors for the same name, on other strings, guard against. The outcome is recorded on the
    program as an [AnchorResolutionReport][ofrak.core.anchored_markup.AnchorResolutionReport].

    Requires function→string references, derived from the data cross-references that only the
    Ghidra and Binary Ninja backends provide; raises
    [ReferencedDataUnavailableError][ofrak.core.referenced_strings.ReferencedDataUnavailableError]
    with any other backend. Raises a `ValueError` for invalid anchors, before resolving any (see
    [validate][ofrak.core.anchored_markup.ApplyAnchoredMarkupConfig.validate]).
    """

    targets = (Program,)

    async def modify(self, resource: Resource, config: ApplyAnchoredMarkupConfig) -> None:
        config.validate()
        program = await resource.view_as(Program)
        functions_by_string: Dict[str, Set[int]] = dict()
        for function_vaddr, texts in (await get_function_string_references(program)).items():
            for text in texts:
                functions_by_string.setdefault(text, set()).add(function_vaddr)

        anchors_by_name: Dict[str, List[Anchor]] = dict()
        for anchor in config.anchors:
            anchors_by_name.setdefault(anchor.name, []).append(anchor)
        misses: List[str] = []
        matches: Dict[str, Tuple[int, ...]] = dict()
        ambiguous: Dict[str, Tuple[int, ...]] = dict()
        missing_strings: Dict[str, Tuple[str, ...]] = dict()
        for name, anchors in anchors_by_name.items():
            missing = tuple(
                cast(str, anchor.value)
                for anchor in anchors
                if cast(str, anchor.value) not in functions_by_string
            )
            if missing:
                missing_strings[name] = missing
            found = [
                functions_by_string[cast(str, anchor.value)]
                for anchor in anchors
                if cast(str, anchor.value) in functions_by_string
            ]
            if not found:
                misses.append(name)
                continue
            candidates = tuple(sorted(set.intersection(*found)))
            if not candidates:
                # The anchors disagree on which function this is
                ambiguous[name] = tuple(sorted(set.union(*found)))
            elif len(candidates) > 1 and not config.apply_to_all:
                ambiguous[name] = candidates
            else:
                matches[name] = candidates

        # Two differently-named anchors on one function would leave it with whichever name came
        # last, so neither is applied.
        names_by_function: Dict[int, Set[str]] = dict()
        for name, function_vaddrs in matches.items():
            for function_vaddr in function_vaddrs:
                names_by_function.setdefault(function_vaddr, set()).add(name)
        for names in names_by_function.values():
            if len(names) > 1:
                for name in names:
                    if name in matches:
                        ambiguous[name] = matches.pop(name)

        complex_blocks = await get_complex_blocks_by_vaddr(program)
        hits: Dict[str, Tuple[int, ...]] = dict()
        conflicts: Dict[str, Tuple[int, ...]] = dict()
        for name, function_vaddrs in matches.items():
            comments = [anchor.comment for anchor in anchors_by_name[name] if anchor.comment]
            applied: List[int] = []
            conflicting: List[int] = []
            for function_vaddr in function_vaddrs:
                if await apply_function_markup(complex_blocks[function_vaddr], name, comments):
                    applied.append(function_vaddr)
                else:
                    conflicting.append(function_vaddr)
            if applied:
                hits[name] = tuple(applied)
            if conflicting:
                conflicts[name] = tuple(conflicting)

        resource.add_attributes(
            AnchorResolutionReport(
                hits=hits,
                misses=tuple(misses),
                ambiguous={name: ambiguous[name] for name in sorted(ambiguous)},
                conflicts=conflicts,
                missing_strings=missing_strings,
            )
        )


async def get_complex_blocks_by_vaddr(program: Program) -> Dict[int, ComplexBlock]:
    """
    :param program: A program unpacked into complex blocks

    :return: Every complex block (function) of the program, by virtual address
    """
    complex_blocks = await program.resource.get_descendants_as_view(
        ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
    )
    return {complex_block.virtual_address: complex_block for complex_block in complex_blocks}


def get_analyst_name(complex_block: ComplexBlock) -> Optional[str]:
    """
    :param complex_block: A function

    :return: The name an analyst gave the function with
    [RenameComplexBlockModifier][ofrak.core.complex_block.RenameComplexBlockModifier], if the
    function still has that name, and None otherwise
    """
    resource = complex_block.resource
    if not resource.has_attributes(AnalystNameAttributes):
        return None
    name = resource.get_attributes(AnalystNameAttributes).name
    # The provenance marker only counts if the function still has the name it recorded
    return name if name == complex_block.name else None


async def apply_function_markup(
    complex_block: ComplexBlock, name: Optional[str], comments: Iterable[str]
) -> bool:
    """
    Name a function and add comments to it, skipping comments it already has so that applying the
    same markup twice changes nothing. Nothing is applied to a function an analyst already gave
    another name.

    :param complex_block: The function
    :param name: The function's new name, or None to keep its current name
    :param comments: Comments to add to the whole function

    :return: False if the function already has a different name given by an analyst, so that
    nothing was applied, and True otherwise
    """
    resource = complex_block.resource
    existing_name = get_analyst_name(complex_block)
    if name is not None and existing_name is not None and existing_name != name:
        return False
    if name is not None:
        await resource.run(RenameComplexBlockModifier, RenameComplexBlockModifierConfig(name))
    existing_comments: Set[str] = set()
    if resource.has_attributes(CommentsAttributes):
        existing_comments.update(resource.get_attributes(CommentsAttributes).comments.get(None, ()))
    for comment in comments:
        if comment not in existing_comments:
            await resource.run(AddCommentModifier, AddCommentModifierConfig((None, comment)))
            existing_comments.add(comment)
    return True


def parse_anchor_set(text: str) -> ApplyAnchoredMarkupConfig:
    """
    Parse an anchor set written in JSON or YAML. The document is either a list of anchors or a
    mapping with an `anchors` list and an optional `apply_to_all` flag. Each anchor is a mapping
    with a `name`, a `value`, an optional `type` (default and only supported value: `STRING`) and
    an optional `comment`, for example:

    ```yaml
    apply_to_all: false
    anchors:
      - name: verify_image_policy
        value: "Not enable the secure boot"
        comment: Aggregates secure-boot policy before image verification.
    ```

    Several anchors may have the same name, to identify one function by several of its strings.

    :param text: The anchor set document

    :raises ValueError: if the document does not describe a valid anchor set

    :return: A config for
    [ApplyAnchoredMarkupModifier][ofrak.core.anchored_markup.ApplyAnchoredMarkupModifier]
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise ValueError(f"An anchor set must be JSON or YAML: {error}")
    if isinstance(document, list):
        document = {"anchors": document}
    if not isinstance(document, dict) or not isinstance(document.get("anchors"), list):
        raise ValueError(
            "An anchor set must be a list of anchors or a mapping with an 'anchors' list"
        )
    unknown_keys = set(document.keys()) - {"anchors", "apply_to_all"}
    if unknown_keys:
        raise ValueError(f"Unknown anchor set keys: {', '.join(sorted(map(str, unknown_keys)))}")
    apply_to_all = document.get("apply_to_all", False)
    if not isinstance(apply_to_all, bool):
        raise ValueError(f"apply_to_all must be true or false, not {apply_to_all!r}")
    config = ApplyAnchoredMarkupConfig(
        anchors=[_parse_anchor(raw_anchor) for raw_anchor in document["anchors"]],
        apply_to_all=apply_to_all,
    )
    config.validate()
    return config


async def load_anchor_set(path: str) -> ApplyAnchoredMarkupConfig:
    """
    Read an anchor set from a UTF-8 JSON or YAML file; see
    [parse_anchor_set][ofrak.core.anchored_markup.parse_anchor_set] for the format.

    :param path: Path to the anchor set file

    :raises ValueError: if the file does not describe a valid anchor set

    :return: A config for
    [ApplyAnchoredMarkupModifier][ofrak.core.anchored_markup.ApplyAnchoredMarkupModifier]
    """
    with open(path, encoding="utf-8") as f:
        return parse_anchor_set(f.read())


def _parse_anchor(raw_anchor: Any) -> Anchor:
    if not isinstance(raw_anchor, dict):
        raise ValueError(f"An anchor must be a mapping, not {raw_anchor!r}")
    unknown_keys = set(raw_anchor.keys()) - {"name", "type", "value", "comment"}
    if unknown_keys:
        raise ValueError(f"Unknown anchor keys: {', '.join(sorted(map(str, unknown_keys)))}")
    missing_keys = {"name", "value"} - set(raw_anchor.keys())
    if missing_keys:
        raise ValueError(f"Anchor {raw_anchor!r} is missing {', '.join(sorted(missing_keys))}")
    anchor_type_name = raw_anchor.get("type", AnchorType.STRING.name)
    if anchor_type_name not in AnchorType.__members__:
        raise ValueError(
            f"Unknown anchor type {anchor_type_name!r}; supported types: "
            f"{', '.join(AnchorType.__members__)}"
        )
    name = raw_anchor["name"]
    if not isinstance(name, str):
        raise ValueError(f"The name of anchor {raw_anchor!r} must be a string")
    comment = raw_anchor.get("comment")
    if comment is not None and not isinstance(comment, str):
        raise ValueError(f"The comment of anchor {name!r} must be a string")
    value = raw_anchor["value"]
    return Anchor(
        name=_join_surrogate_pairs(name),
        anchor_type=AnchorType[anchor_type_name],
        value=_join_surrogate_pairs(value) if isinstance(value, str) else value,
        comment=None if comment is None else _join_surrogate_pairs(comment),
    )


def _join_surrogate_pairs(text: str) -> str:
    """
    YAML parsers decode an escaped character outside the Basic Multilingual Plane, written as a
    UTF-16 surrogate pair like JSON does ("\\ud83d\\ude00"), into two lone surrogates.

    :raises ValueError: if `text` has a surrogate that is not part of a pair

    :return: `text` with each surrogate pair replaced by the character it encodes
    """
    try:
        return text.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeDecodeError:
        raise ValueError(f"{text!r} is not valid Unicode")
