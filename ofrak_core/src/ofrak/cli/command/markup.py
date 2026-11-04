import argparse
import os
from typing import Iterable, List

from ofrak import OFRAKContext
from ofrak.cli.ofrak_cli import OfrakCommandRunsScript
from ofrak.core.anchored_markup import (
    AnchorResolutionReport,
    ApplyAnchoredMarkupModifier,
    load_anchor_set,
)
from ofrak.core.portable_markup import (
    MarkupImportConfig,
    MarkupImportModifier,
    MarkupImportReport,
    MarkupMatch,
    PortableMarkup,
    export_portable_markup,
    load_portable_markup,
    save_portable_markup,
)
from ofrak.core.program import Program


class MarkupCommand(OfrakCommandRunsScript):
    """
    Apply function markup to a binary, headlessly: from an anchor set, or from portable markup
    exported from another build. Optionally export the binary's resulting markup as portable
    markup, so that it can be carried on to the next build.
    """

    def create_parser(self, parser: argparse._SubParsersAction):
        subparser = parser.add_parser(
            "markup",
            help="Name and comment functions from an anchor set or from portable markup",
            description="Import a program as an OFRAK resource, name and comment its functions "
            "from an anchor set (YAML or JSON) or from portable markup exported from another "
            "build of the program, and print which markup was applied and which was not. Needs "
            "a backend that provides data cross-references, e.g. `-b ghidra`.",
        )
        subparser.add_argument("filename", help="Program to apply the markup to")
        source = subparser.add_mutually_exclusive_group(required=True)
        source.add_argument("--anchors", help="Anchor set to apply (YAML or JSON)")
        source.add_argument(
            "--portable-markup", help="Portable markup to import (JSON, from `--output`)"
        )
        subparser.add_argument(
            "--similarity-threshold",
            type=float,
            default=0.5,
            help="With --portable-markup: a match needs a string-set similarity greater than this",
        )
        subparser.add_argument(
            "-o",
            "--output",
            help="Write the program's resulting markup to this file, as portable markup",
        )
        self.add_ofrak_arguments(subparser)
        return subparser

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: argparse.Namespace):
        root_resource = await ofrak_context.create_root_resource_from_file(args.filename)
        await root_resource.unpack()
        if args.anchors is not None:
            await root_resource.run(
                ApplyAnchoredMarkupModifier, await load_anchor_set(args.anchors)
            )
            print(format_anchor_report(root_resource.get_attributes(AnchorResolutionReport)))
        else:
            markup = await load_portable_markup(ofrak_context, args.portable_markup)
            await root_resource.run(
                MarkupImportModifier, MarkupImportConfig(markup, args.similarity_threshold)
            )
            print(format_import_report(markup, root_resource.get_attributes(MarkupImportReport)))
        if args.output is not None:
            exported = await export_portable_markup(
                await root_resource.view_as(Program), os.path.basename(args.filename)
            )
            await save_portable_markup(ofrak_context, exported, args.output)
            print(f"Wrote the markup of {_count_marked_up(exported)} functions to {args.output}")


def format_anchor_report(report: AnchorResolutionReport) -> str:
    """
    :param report: What applying an anchor set did

    :return: A human-readable summary of the report
    """
    lines = [f"Applied {len(report.hits)} anchors:"]
    lines += [f"  {name} -> {_format_vaddrs(vaddrs)}" for name, vaddrs in report.hits.items()]
    lines.append(f"Missed {len(report.misses)} anchors (no function references the string):")
    lines += [f"  {name}" for name in report.misses]
    lines.append(f"Did not apply {len(report.ambiguous)} ambiguous anchors:")
    lines += [
        f"  {name}: candidates {_format_vaddrs(vaddrs)}"
        for name, vaddrs in report.ambiguous.items()
    ]
    lines.append(
        f"Did not apply {len(report.conflicts)} anchors to functions an analyst named otherwise:"
    )
    lines += [f"  {name}: {_format_vaddrs(vaddrs)}" for name, vaddrs in report.conflicts.items()]
    lines.append(f"Strings of {len(report.missing_strings)} anchors that no function references:")
    lines += [
        f"  {name}: {', '.join(map(repr, strings))}"
        for name, strings in report.missing_strings.items()
    ]
    return "\n".join(lines)


def format_import_report(markup: PortableMarkup, report: MarkupImportReport) -> str:
    """
    :param markup: The imported portable markup
    :param report: What importing it did

    :return: A human-readable summary of the report
    """
    lines = [
        f"Imported markup of {_count_marked_up(markup)} functions from {markup.program}:",
        f"Applied {len(report.matched)} records:",
    ]
    lines += _format_matches(report.matched)
    lines.append(f"Did not apply {len(report.ambiguous)} ambiguous records:")
    lines += _format_matches(report.ambiguous)
    lines.append(f"Did not apply {len(report.unmatched)} unmatched records:")
    lines += _format_matches(report.unmatched)
    lines.append(
        f"Did not apply {len(report.conflicts)} records to functions an analyst named otherwise:"
    )
    lines += _format_matches(report.conflicts)
    return "\n".join(lines)


def _count_marked_up(markup: PortableMarkup) -> int:
    return sum(1 for function in markup.functions if function.has_markup())


def _format_matches(matches: Iterable[MarkupMatch]) -> List[str]:
    return [
        f"  {match.name or f'(record {match.record_index}, comments only)'} -> "
        f"{_format_vaddrs(match.function_vaddrs) or 'none'} (similarity {match.similarity:.2f})"
        for match in matches
    ]


def _format_vaddrs(vaddrs: Iterable[int]) -> str:
    return ", ".join(hex(vaddr) for vaddr in vaddrs)
