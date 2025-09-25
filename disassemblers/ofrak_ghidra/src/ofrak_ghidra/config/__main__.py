import argparse

from ofrak_ghidra.config.ofrak_ghidra_config import (
    save_ghidra_config,
    OfrakGhidraConfig,
    load_ghidra_config,
    restore_default_ghidra_config,
)


def _dump_config(args):
    print(load_ghidra_config().to_yaml())


def _import_config(args):
    with open(args.config_path) as f:
        raw_new_config = f.read()
        new_config = OfrakGhidraConfig.from_yaml(raw_new_config)
        save_ghidra_config(new_config)


def _restore_config(args):
    restore_default_ghidra_config()


parser = argparse.ArgumentParser(description="Read and write OFRAK Ghidra config")
command_parser = parser.add_subparsers()

dump_parser = command_parser.add_parser(
    "dump", description="Dump the current OFRAK Ghidra config as yaml to stdout"
)
dump_parser.set_defaults(func=_dump_config)
import_parser = command_parser.add_parser(
    "import",
    description="Loads a complete OFRAK Ghidra config from a path to a yaml file and saves it as the current Ghidra config.",
)
import_parser.add_argument(
    "config_path", type=str, help="Path to config file to import", metavar="config-path"
)
import_parser.set_defaults(func=_import_config)
restore_parser = command_parser.add_parser(
    "restore", description="Restore the default OFRAK Ghidra settings."
)
restore_parser.set_defaults(func=_restore_config)


if __name__ == "__main__":
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_usage()
