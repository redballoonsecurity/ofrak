import sys

from ofrak.cli.command.deps import DepsCommand
from ofrak.cli.command.gui import GUICommand
from ofrak.cli.command.identify import IdentifyCommand
from ofrak.cli.command.license import LicenseCommand
from ofrak.cli.command.list import ListCommand
from ofrak.cli.command.unpack import UnpackCommand
from ofrak.cli.ofrak_cli import OFRAKCommandLineInterface


def main():  # pragma: no cover
    ofrak_cli = OFRAKCommandLineInterface(
        (
            ListCommand(),
            DepsCommand(),
            IdentifyCommand(),
            UnpackCommand(),
            GUICommand(),
            LicenseCommand(),
        )
    )
    ofrak_cli.parse_and_run(sys.argv[1:])


if __name__ == "__main__":
    main()
