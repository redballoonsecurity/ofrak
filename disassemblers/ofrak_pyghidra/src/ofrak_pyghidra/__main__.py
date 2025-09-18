import argparse
import time
import json

from ofrak_pyghidra.standalone.pyghidra_analysis import unpack


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
