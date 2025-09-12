import argparse

from ofrak import OFRAKContext
from ofrak.cli.ofrak_cli import OfrakCommandRunsScript
from ofrak.core.magic import Magic
from ofrak.gui.server import open_gui
from ofrak.resource import Resource


class IdentifyCommand(OfrakCommandRunsScript):
    def create_parser(self, parser: argparse._SubParsersAction):
        subparser = parser.add_parser(
            "identify",
            help="Identify all known structures in the binary",
            description="Import a file as an OFRAK resource, then identifies it and prints all the"
            " tags and attributes.",
        )
        subparser.add_argument("filename", help="File to identify")
        self.add_ofrak_arguments(subparser)

        # GUI args
        subparser.add_argument(
            "--gui",
            action="store_true",
            help="Open the OFRAK GUI after unpacking",
            default=False,
        )
        subparser.add_argument(
            "-gH",
            "--gui-hostname",
            action="store",
            help="Set GUI server host address.",
            default="127.0.0.1",
        )
        subparser.add_argument(
            "-gp",
            "--gui-port",
            action="store",
            type=int,
            help="Set GUI server host port.",
            default=8080,
        )
        subparser.add_argument(
            "--gui-no-browser",
            action="store_true",
            help="Don't open the browser to the OFRAK GUI",
        )

        return subparser

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: argparse.Namespace):
        print(f"Identifying file: {args.filename}\n")
        root_resource = await ofrak_context.create_root_resource_from_file(args.filename)

        await root_resource.identify()
        print(await IdentifyCommand.print_info(root_resource))

        if args.gui:
            server = await open_gui(
                args.gui_hostname,
                args.gui_port,
                focus_resource=root_resource,
                open_in_browser=(not args.gui_no_browser),
            )
            await server.run_until_cancelled()

    @staticmethod
    async def print_info(resource: Resource) -> str:
        output = ""

        output += "= Tags = \n"
        for tag in resource.get_tags():
            output += f"  {tag}\n"

        output += "= Attributes =\n"
        for attributes_t, attribute in resource.get_model().attributes.items():
            if attributes_t is Magic:
                output += (
                    f"  Magic: "
                    f"\n   Mime: {attribute.mime}"
                    f"\n   Descriptor: {attribute.descriptor}\n"
                )
            else:
                output += f"  {attribute}"

        return output
