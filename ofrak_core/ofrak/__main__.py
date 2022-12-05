from ofrak.ofrak_cli import (
    ListSubCommand,
    DepsSubCommand,
    OFRAKEnvironment,
    OFRAKCommandLineInterface,
)

if __name__ == "__main__":
    ofrak_env = OFRAKEnvironment()
    subcommands = [ListSubCommand(), DepsSubCommand()]
    ofrak_cli = OFRAKCommandLineInterface(ofrak_env, subcommands)
    ofrak_cli.parse_and_run()
