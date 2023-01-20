import logging
import webbrowser
from argparse import ArgumentDefaultsHelpFormatter, Namespace

from ofrak.gui.server import start_server
from ofrak.ofrak_context import OFRAKContext

from ofrak.cli.ofrak_cli import OfrakCommandRunsScript

LOGGER = logging.getLogger(__name__)


class GUICommand(OfrakCommandRunsScript):
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
        self.add_ofrak_arguments(gui_parser)
        return gui_parser

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: Namespace):  # pragma: no cover
        url = f"http://{args.hostname}:{args.port}"
        print(f"GUI is being served on {url}")
        webbrowser.open(url)

        await start_server(ofrak_context, args.hostname, args.port)  # type: ignore
