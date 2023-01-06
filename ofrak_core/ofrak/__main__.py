import sys

from ofrak.cli.command.deps import DepsSubCommand
from ofrak.cli.command.identify import Identify
from ofrak.cli.command.list import ListSubCommand
from ofrak.cli.command.unpack import Unpack
from ofrak.cli.ofrak_cli import OFRAKCommandLineInterface

if __name__ == "__main__":
    ofrak_cli = OFRAKCommandLineInterface(
        (ListSubCommand(), DepsSubCommand(), Identify(), Unpack())
    )
    ofrak_cli.parse_and_run(sys.argv[1:])
