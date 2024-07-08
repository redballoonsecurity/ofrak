from argparse import ArgumentDefaultsHelpFormatter, Namespace

from ofrak import OFRAKContext
from ofrak.cli.ofrak_cli import OfrakCommandRunsScript, OFRAKEnvironment
from ofrak.license import do_license_check


class LicenseCommand(OfrakCommandRunsScript):
    def create_parser(self, ofrak_subparsers):  # pragma: no cover
        argument_parser = ofrak_subparsers.add_parser(
            "license",
            help="Configure the OFRAK license",
            description="Configure the OFRAK license",
            formatter_class=ArgumentDefaultsHelpFormatter,
        )
        argument_parser.add_argument(
            "-c",
            "--community",
            action="store_true",
            default=False,
            help="Use the community license",
        )
        argument_parser.add_argument(
            "--i-agree", action="store_true", default=False, help="Agree to the license terms"
        )
        argument_parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            default=False,
            help="Replace the current license with a new configuration",
        )
        return argument_parser

    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):  # pragma: no cover
        do_license_check(
            force_replace=args.force, force_agree=args.i_agree, force_community=args.community
        )

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: Namespace):  # pragma: no cover
        pass
