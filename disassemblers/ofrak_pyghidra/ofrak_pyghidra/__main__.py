import argparse
import time
import json

from ofrak_pyghidra.standalone.pyghidra_analysis import unpack


def _analyze_binary(args):
    start = time.time()
    res = unpack(args.infile, args.decompile, args.language)
    with open(args.outfile, "w") as fh:
        json.dump(res, fh, indent=4)
    print(f"PyGhidra analysis took {time.time() - start} seconds")


def parse_args():
    parser = argparse.ArgumentParser(description="Run PyGhidra scripts and OFRAK Components.")
    command_parser = parser.add_subparsers()

    start_parser = command_parser.add_parser("analyze", description="Start the OFRAK Ghidra server")
    start_parser.set_defaults(func=_analyze_binary)
    start_parser.add_argument(
        "--infile", "-i", type=str, required=True, help="The binary to be analyzed."
    )
    start_parser.add_argument(
        "--outfile", "-o", type=str, required=True, help="The output json file."
    )
    start_parser.add_argument("--language", "-l", default=None, help="Ghidra language id")
    start_parser.add_argument(
        "--decompile",
        "-d",
        action="store_true",
        required=False,
        default=False,
        help="decompile functions in cache",
    )

    return parser


if __name__ == "__main__":
    parser = parse_args()
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_usage()
