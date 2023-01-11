import sys

from ofrak.ofrak_cli import OFRAKCommandLineInterface

if __name__ == "__main__":
    ofrak_cli = OFRAKCommandLineInterface()
    ofrak_cli.parse_and_run(sys.argv[1:])
