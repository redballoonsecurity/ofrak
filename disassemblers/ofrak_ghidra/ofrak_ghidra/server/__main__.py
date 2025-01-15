import argparse
import os
import stat
import subprocess
import sys

from ofrak_ghidra.constants import (
    GHIDRA_START_SERVER_SCRIPT,
    GHIDRA_PATH,
    CORE_OFRAK_GHIDRA_SCRIPTS,
    GHIDRA_USER,
    GHIDRA_PASS,
    GHIDRA_REPOSITORY_HOST,
    GHIDRA_REPOSITORY_PORT,
)


def _run_ghidra_server(*args):
    if sys.platform == "linux" or sys.platform == "darwin":
        os.chmod(
            GHIDRA_START_SERVER_SCRIPT, os.stat(GHIDRA_START_SERVER_SCRIPT).st_mode | stat.S_IEXEC
        )
        subprocess.call(
            [
                GHIDRA_START_SERVER_SCRIPT,
                GHIDRA_PATH,
                CORE_OFRAK_GHIDRA_SCRIPTS,
                GHIDRA_USER,
                GHIDRA_PASS,
                GHIDRA_REPOSITORY_HOST,
                str(GHIDRA_REPOSITORY_PORT),
            ]
        )
    else:
        raise NotImplementedError(f"Native OFRAK Ghidra server not supported for {sys.platform}!")


def _stop_ghidra_server(*args):
    if sys.platform == "linux" or sys.platform == "darwin":
        subprocess.call([os.path.join(GHIDRA_PATH, "server", "ghidraSvr"), "stop"])
    else:
        raise NotImplementedError(f"Native OFRAK Ghidra server not supported for {sys.platform}!")


parser = argparse.ArgumentParser(description="Manage OFRAK Ghidra server")
command_parser = parser.add_subparsers()

start_parser = command_parser.add_parser("start", description="Start the OFRAK Ghidra server")
start_parser.set_defaults(func=_run_ghidra_server)
stop_parser = command_parser.add_parser("stop", description="Stop the OFRAK Ghidra server")
stop_parser.set_defaults(func=_stop_ghidra_server)


if __name__ == "__main__":
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_usage()
