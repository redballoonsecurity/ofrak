import argparse
import time
import json

from ofrak_pyghidra.standalone.pyghidra_analysis import unpack
from ofrak_pyghidra.standalone.pyghidra_script import run_script


def script_command(args):  # pragma: no cover
    with open(args.script) as fh:
        script_source = fh.read()
    result, analysis = run_script(
        args.infile,
        script_source,
        language=args.language,
        refresh_analysis=args.outfile is not None,
    )
    if args.outfile is not None:
        with open(args.outfile, "w") as fh:
            json.dump(analysis, fh, indent=4)
        print(f"Wrote refreshed analysis cache to {args.outfile}")
    print(f"Script result: {result!r}")


def main():  # pragma: no cover
    parser = argparse.ArgumentParser(description="Run PyGhidra scripts and OFRAK Components.")
    command_parser = parser.add_subparsers()
    start_parser = command_parser.add_parser(
        "analyze",
        description="Creates a cache json file from a binary to be used with the CachedDisassemblyAnalyzer.",
    )
    start_parser.add_argument(
        "--infile", "-i", type=str, required=True, help="The binary to be analyzed."
    )
    start_parser.add_argument(
        "--outfile", "-o", type=str, required=True, help="The output json file."
    )
    start_parser.add_argument(
        "--language",
        "-l",
        default=None,
        help="Ghidra language id, not needed for ELF but other formats might need it. Example: 'x86:LE:32:default'",
    )
    start_parser.add_argument(
        "--decompile",
        "-d",
        action="store_true",
        required=False,
        default=False,
        help="Decompile functions in cache",
    )
    script_parser = command_parser.add_parser(
        "script",
        description="Run a PyGhidra script against a binary, reusing and saving the Ghidra "
        "project state between runs.",
    )
    script_parser.add_argument(
        "--infile", "-i", type=str, required=True, help="The binary to run the script against."
    )
    script_parser.add_argument(
        "--script",
        "-s",
        type=str,
        required=True,
        help="Path to a Python script, executed with `flat_api`, `currentProgram`, and `monitor`"
        " in scope. The script can set a variable named `result` to print a value.",
    )
    script_parser.add_argument(
        "--language",
        "-l",
        default=None,
        help="Ghidra language id, only used the first time the binary is imported. Example: 'x86:LE:32:default'",
    )
    script_parser.add_argument(
        "--outfile",
        "-o",
        type=str,
        default=None,
        help="If provided, re-extract the analysis cache after the script runs and write it to this json file.",
    )
    script_parser.set_defaults(func=script_command)
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        # Handle the analyze command
        start = time.time()
        res = unpack(args.infile, args.decompile, args.language)
        with open(args.outfile, "w") as fh:
            json.dump(res, fh, indent=4)
        print(f"PyGhidra analysis took {time.time() - start} seconds")


if __name__ == "__main__":
    main()
