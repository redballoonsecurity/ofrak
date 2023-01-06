import argparse

from ofrak import OFRAKContext
from ofrak.cli.ofrak_cli import OfrakCommandRunsScript
from ofrak.core.magic import Magic
from ofrak.resource import Resource


class Identify(OfrakCommandRunsScript):
    def create_parser(self, parser: argparse._SubParsersAction):
        subparser = parser.add_parser(
            "identify",
            help="Identify all known structures in the binary",
            description="Import a file as an OFRAK resource, then identifies it and prints all the"
            " tags and attributes.",
        )
        subparser.add_argument("filename", help="File to identify")
        self.add_ofrak_arguments(subparser)

        return subparser

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: argparse.Namespace):
        print(f"Identifying file: {args.filename}\n")
        root_resource = await ofrak_context.create_root_resource_from_file(args.filename)

        await root_resource.identify()
        print(await Identify._print_info(root_resource))

    @staticmethod
    async def _print_info(resource: Resource) -> str:
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
