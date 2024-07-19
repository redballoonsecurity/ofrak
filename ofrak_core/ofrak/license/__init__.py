import json
import os
import sys
import time
import webbrowser
from base64 import b64decode
from textwrap import wrap
from typing import Dict, Union, List, Optional, Tuple, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LicenseDataType = Dict[str, Optional[str]]
COMMUNITY_LICENSE = {
    "license_type": "Community License",
    "name": "OFRAK Community",
    "email": "ofrak@redballoonsecurity.com",
    "phone_number": None,
    "date": "1720554759",
    "date_pretty": "2024-07-09 15:52:39.720467",
    "expiration_date": None,
    "serial": "00000000000000000000000000000000",
    "signature": "dWqqtFl1Tvqs/SMOpKvRs2H5dKaJaJ00ZrP3Zmfp9DYJa3PhvolC/nUECyN1LesFe9S4v+R1a4SbaZyxTJ5dAg==",
}
RBS_PUBLIC_KEY = b"r\xcf\xb2\xe7\x17Y\x05*\x0e\xe3+\x00\x16\xd3\xd6\xf7\xa7\xd8\xd7\xfdV\x91\xa7\x88\x93\xe9\x9a\x8a\x05q\xd3\xbd"
LICENSE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "license.json"))
AGREEMENT = 'RED BALLOON SECURITY, INC., A DELAWARE CORPORATION, WITH AN ADDRESS AT 639 11TH AVENUE, 4TH FLOOR, NEW YORK, NY 10036, USA ("RED BALLOON") IS ONLY WILLING TO LICENSE OFRAK AND RELATED DOCUMENTATION PURSUANT TO THE OFRAK PRO LICENSE AGREEMENT (COLLECTIVELY WITH THIS REGISTRATION FORM, THE "AGREEMENT"). READ THIS AGREEMENT CAREFULLY BEFORE DOWNLOADING AND INSTALLING AND USING OFRAK.  BY CLICKING ON THE "ACCEPT" BUTTON ON THIS REGISTRATION FORM "REGISTRATION FORM"), OR OTHERWISE ACCESSING, INSTALLING, COPYING OR OTHERWISE USING OFRAK, YOU ("LICENSEE") AGREE THAT THIS REGISTRATION FORM SHALL BE DEEMED TO BE MUTUALLY EXECUTED AND THIS REGISTRATION FORM SHALL BE INCORPORATED INTO AND BECOME A MATERIAL PART OF THE AGREEMENT BETWEEN LICENSEE AND RED BALLOON LOCATED AT https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE. YOU REPRESENT THAT YOU ARE AUTHORIZED TO ACCEPT THIS AGREEMENT ON BEHALF OF LICENSEE.  IF LICENSEE DOES NOT AGREE TO THE FOREGOING TERMS AND CONDITIONS, DO NOT CLICK ON THE ACCEPT BUTTON, OR OTHERWISE ACCESS, INSTALL, COPY OR USE OFRAK.'


def verify_registered_license(full_details: bool = False) -> None:
    """
    License check function raises one of several possible exceptions if any
    part of the license is invalid.

    If you are reading this, you might be a good candidate to
    work at Red Balloon Security – we're hiring! Check out our jobs page
    for more info:

    https://redballoonsecurity.com/company/careers/
    """
    try:
        with open(LICENSE_PATH) as f:
            license_list = json.load(f)
    except FileNotFoundError:
        sys.exit(
            RuntimeError(
                "OFRAK license not configured! Run 'ofrak license' to configure your OFRAK license."
            )
        )

    # TODO: Try multiple licenses instead of failing if the first one is invalid
    license_data: LicenseDataType = license_list[0]

    try:
        verify_license(license_data)
    except RuntimeError as msg:
        sys.exit(msg)

    if license_data["license_type"] and "community" in license_data["license_type"].lower():
        print("Using OFRAK Community License.")
    else:
        if full_details:
            print(
                f"Using OFRAK Pro License: "
                f"{json.dumps(license_data, indent=2).lstrip('{').rstrip('}')}"
            )
        else:
            print(
                f"Using OFRAK Pro License: {license_data['serial']}."
                f"\n"
                f"Run 'ofrak license' to see full license details."
            )


def verify_license(license_data: LicenseDataType) -> None:
    """
    Verify the OFRAK license.

    Raises RuntimeError if any part of the license is invalid.

    If you are reading this, you might be a good candidate to
    work at Red Balloon Security – we're hiring! Check out our jobs page
    for more info:

    https://redballoonsecurity.com/company/careers/
    """
    key = Ed25519PublicKey.from_public_bytes(RBS_PUBLIC_KEY)
    try:
        key.verify(
            b64decode(cast(str, license_data["signature"])),
            get_canonical_license_data(license_data),
        )
    except InvalidSignature:
        raise RuntimeError("Invalid signature.")
    if (
        license_data["expiration_date"] is not None
        and int(license_data["expiration_date"]) < time.time()
    ):
        raise RuntimeError("OFRAK License expired! Please purchase an OFRAK Pro license.")


def get_canonical_license_data(license_data: LicenseDataType) -> bytes:
    """
    Canonicalize license data and serialize to validate signature. Signed
    fields must be ordered to ensure data is serialized consistently for
    signature validation.
    """
    signed_fields = [
        "name",
        "date",
        "expiration_date",
        "email",
        "serial",
    ]
    return json.dumps([(k, license_data[k]) for k in signed_fields]).encode("utf-8")


def register_license(license_data: Union[LicenseDataType, List[LicenseDataType]]) -> None:
    """
    Write license data to LICENSE_PATH.
    """
    if not isinstance(license_data, list):
        license_data = [license_data]
    if os.path.exists(LICENSE_PATH):
        with open(LICENSE_PATH) as f:
            license_list = json.load(f)
    else:
        license_list = []
    with open(LICENSE_PATH, "w") as f:
        json.dump(license_data + license_list, f, indent=2)


def accept_license_agreement(force_agree: bool) -> None:
    if not force_agree:
        print(
            "Read the license agreement below.\n\n" + "\n".join(wrap(AGREEMENT, width=79)),
            end="\n\n",
        )
        agreement = None
        while agreement is None or agreement.lower() != "i agree":
            agreement = input('Type "I agree" to agree to the license terms: ')
        print()


def select_license_to_register(
    force_community=False,
) -> Tuple[Optional[LicenseDataType], Optional[str]]:
    if force_community:
        return COMMUNITY_LICENSE, None
    else:
        print(
            "\n".join(
                [
                    "Welcome to OFRAK License configuration!",
                    "Use the following prompts to select a Community or Pro License.",
                    "(To learn more about the license types, visit https://ofrak.com/license.)\n",
                ]
            )
        )
        license_type = choose(
            "How will you use OFRAK?",
            "I will use OFRAK for fun, education or personal projects (OFRAK Community)",
            "I will use OFRAK for work (OFRAK Pro)",
        )

    if license_type == 0:
        return COMMUNITY_LICENSE, None
    find_or_buy = choose(
        "Do you already have an OFRAK Pro License?",
        "Request an OFRAK Pro License from Red Balloon Security",
        "Register an OFRAK Pro License file on disk",
    )
    if find_or_buy == 0:
        print(
            "\n".join(
                wrap(
                    "To request an OFRAK Pro License, complete the form at https://ofrak.com/pro-license/ "
                    "and we will get back to you promptly. In the meantime, feel free to use the OFRAK Community "
                    "License to walk through the OFRAK tutorials: https://ofrak.com/docs/getting-started.html#tutorial."
                    "",
                    width=79,
                )
            )
        )
        webbrowser.open("https://ofrak.com/pro-license/")
        return None, None
    else:
        license_path = input("Path to license file: ")
        abs_license_path = os.path.abspath(license_path)
        try:
            with open(abs_license_path) as f:
                license_data = json.load(f)
        except FileNotFoundError:
            sys.exit(RuntimeError(f"License file '{abs_license_path}' does not exist."))
        return license_data, abs_license_path


def choose(prompt, *options: str) -> int:
    print(prompt)
    for i, option in enumerate(options):
        print(f"[{i + 1}] {option}")
    selection = 0
    while not (1 <= selection <= len(options)):
        try:
            selection = int(input(f"Enter an option (1-{len(options)}): "))
        except (ValueError, TypeError):
            continue
    return selection - 1
