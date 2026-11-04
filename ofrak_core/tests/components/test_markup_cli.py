"""
This module tests the `ofrak markup` command, which applies anchor sets and portable markup to a
binary headlessly.

Requirements Mapping:
- REQ2.6
- REQ2.7
"""
import os

import pytest

from ofrak.cli.command.markup import MarkupCommand
from ofrak.cli.ofrak_cli import OFRAKCommandLineInterface
from ofrak.core import ReferencedDataUnavailableError
from .re_markup_experiment import ASSETS_DIR

HELLO = os.path.join(os.path.dirname(__file__), "assets", "hello.out")
HELLO_ANCHORS = os.path.join(ASSETS_DIR, "hello-anchors.yml")


def test_markup_command(ghidra_backend, tmp_path, capsys):
    """
    Test applying an anchor set with `ofrak markup`, exporting the result as portable markup, and
    importing that markup onto a fresh analysis with `ofrak markup` (REQ2.6, REQ2.7).

    This test verifies that:
    - The command reports the applied and missed anchors
    - `--output` writes the program's markup as portable markup, counting the functions with
      markup
    - Importing that markup, with a similarity threshold, applies it to the same function, and is
      reported
    """
    markup_path = str(tmp_path / "hello.markup.json")
    cli = OFRAKCommandLineInterface((MarkupCommand(),))

    cli.parse_and_run(
        ["markup", "-b", "ghidra", HELLO, "--anchors", HELLO_ANCHORS, "-o", markup_path]
    )
    output = capsys.readouterr().out
    assert "Applied 1 anchors:\n  hello_main -> 0x4004c4\n" in output
    assert "Missed 1 anchors (no function references the string):\n  goodbye_main\n" in output
    assert "Did not apply 0 ambiguous anchors:" in output
    assert "Did not apply 0 anchors to functions an analyst named otherwise:" in output
    assert (
        "Strings of 1 anchors that no function references:\n  goodbye_main: 'Goodbye World'\n"
        in output
    )
    assert f"Wrote the markup of 1 functions to {markup_path}" in output

    cli.parse_and_run(
        [
            "markup",
            "-b",
            "ghidra",
            HELLO,
            "--portable-markup",
            markup_path,
            "--similarity-threshold",
            "0.6",
        ]
    )
    output = capsys.readouterr().out
    assert "Imported markup of 1 functions from hello.out:" in output
    assert "Applied 1 records:\n  hello_main -> 0x4004c4 (similarity 1.00)\n" in output
    assert "Did not apply 0 unmatched records:" in output
    assert "Did not apply 0 records to functions an analyst named otherwise:" in output


def test_markup_command_without_data_references():
    """
    Test that `ofrak markup` fails loudly without a backend that provides data cross-references
    (REQ2.6).
    """
    cli = OFRAKCommandLineInterface((MarkupCommand(),))
    with pytest.raises(ReferencedDataUnavailableError):
        cli.parse_and_run(["markup", HELLO, "--anchors", HELLO_ANCHORS])
