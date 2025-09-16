import os
import sys
from argparse import ArgumentDefaultsHelpFormatter, Namespace

from ofrak.cli.ofrak_cli import OFRAKEnvironment, OfrakCommand
from ofrak.license import (
    verify_registered_license,
    LICENSE_PATH,
    select_license_to_register,
    verify_license_is_valid_and_current,
    accept_license_agreement,
    register_license,
)


class LicenseCommand(OfrakCommand):
    def create_parser(self, ofrak_subparsers):
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
        argument_parser.add_argument("-l", "--license", help="Path to a license file to use")
        return argument_parser

    def run(self, ofrak_env: OFRAKEnvironment, args: Namespace):
        try:
            if args.force or not os.path.exists(LICENSE_PATH):
                license_data, license_path = select_license_to_register(
                    force_community=args.community,
                    license_path=args.license,
                )
                if license_data is None:
                    return
                try:
                    verify_license_is_valid_and_current(license_data)
                    accept_license_agreement(args.i_agree, license_data)
                    register_license(license_data)
                    return
                except RuntimeError as msg:
                    file_details = f" License file: {license_path}." if license_path else ""
                    sys.exit(RuntimeError(str(msg) + file_details))
            verify_registered_license(full_details=True)
        except KeyboardInterrupt:
            print()
            sys.exit(-1)
        return
