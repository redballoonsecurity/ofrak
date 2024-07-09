import json
from argparse import ArgumentDefaultsHelpFormatter, Namespace

from ofrak import OFRAKContext
from ofrak.cli.ofrak_cli import OfrakCommandRunsScript, OFRAKEnvironment
from ofrak.license import do_license_check, LICENSE_PATH


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

    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):
        do_license_check(
            force_replace=args.force, force_agree=args.i_agree, force_community=args.community
        )
        with open(LICENSE_PATH) as f:
            # TODO: Change to dump used license once we don't just use the first
            print(json.dumps(json.load(f)[0], indent=2))

    async def ofrak_func(self, ofrak_context: OFRAKContext, args: Namespace):  # pragma: no cover
        pass
