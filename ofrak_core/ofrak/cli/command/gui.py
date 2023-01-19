import logging
import webbrowser
from argparse import ArgumentDefaultsHelpFormatter, Namespace

from ofrak.gui.server import start_server
from ofrak.ofrak_context import OFRAK

from ofrak.cli.ofrak_cli import OFRAKEnvironment, OfrakCommand

LOGGER = logging.getLogger(__name__)


class GUICommand(OfrakCommand):
    def create_parser(self, ofrak_subparsers):
        gui_parser = ofrak_subparsers.add_parser(
            "gui",
            help="Launch the OFRAK GUI server.",
            description="Launch the OFRAK GUI server.",
            formatter_class=ArgumentDefaultsHelpFormatter,
        )
        gui_parser.add_argument(
            "-H",
            "--hostname",
            action="store",
            help="Set GUI server host address.",
            default="127.0.0.1",
        )
        gui_parser.add_argument(
            "-p",
            "--port",
            action="store",
            type=int,
            help="Set GUI server host port.",
            default=8080,
        )
        gui_parser.add_argument(
            "-b",
            "--backend",
            action="store",
            help="Set GUI server backend.",
            default=None,
        )
        gui_parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Enable verbose mode for debugging",
            default=None,
        )
        gui_parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Enable quiet mode to minimize logging",
            default=None,
        )
        return gui_parser

    # pragma: no cover
    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):
        if args.verbose is True:
            ofrak = OFRAK(logging.DEBUG)

        elif args.quiet is True:
            ofrak = OFRAK(logging.WARNING)

        else:
            ofrak = OFRAK(logging.INFO)

        if args.backend is not None:
            if args.backend.lower() == "binary-ninja":
                import ofrak_capstone  # type: ignore
                import ofrak_binary_ninja  # type: ignore

                ofrak.injector.discover(ofrak_capstone)
                ofrak.injector.discover(ofrak_binary_ninja)

            elif args.backend.lower() == "ghidra":
                import ofrak_ghidra  # type: ignore

                ofrak.injector.discover(ofrak_ghidra)

            elif args.backend.lower() == "angr":
                import ofrak_capstone  # type: ignore
                import ofrak_angr  # type: ignore

                ofrak.injector.discover(ofrak_capstone)
                ofrak.injector.discover(ofrak_angr)

        else:
            LOGGER.warning("No disassembler backend specified, so no disassembly will be possible")

        url = f"http://{args.hostname}:{args.port}"
        print(f"GUI is being served on {url}")
        webbrowser.open(url)

        ofrak.run(start_server, args.hostname, args.port)  # type: ignore
