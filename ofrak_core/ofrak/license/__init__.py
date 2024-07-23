import json
import os
import sys
import time
import webbrowser
from base64 import b64decode
from textwrap import wrap
from typing import Dict, Optional, Tuple, cast, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LicenseDataType = Dict[str, Optional[str]]
LicenseListType = List[LicenseDataType]
COMMUNITY_LICENSE = [
    {
        "license_type": "Community License",
        "name": "OFRAK Community",
        "email": "ofrak@redballoonsecurity.com",
        "phone_number": None,
        "date": "1720554759",
        "date_pretty": "2024-07-09 15:52:39.720467",
        "expiration_date": None,
        "expiration_date_pretty": None,
        "serial": "00000000000000000000000000000000",
        "signature": "ihKX823u51cqhvyQmXZ1TGELBiHzYzSIcbpxvZVDaYvpJU9EJKY+Gi8XRFKPfhE1K1DK5UcsMbyynTbAQngHDw==",
    }
]

RBS_PUBLIC_KEY = b"D\xa9LN_\xf3\xdd\x82\xfd\x96\xa5~\x0f=Z\x06\xbe\xdb\xe3`\x1f\xb60\x0e\x07\xe6(\x08\xc3(\x08\x8c"
LICENSE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "license.json"))


def verify_registered_license(full_details: bool = False) -> None:
    """
    Verify presence of a registered OFRAK license.

    If you are reading this, you might be a good candidate to
    work at Red Balloon Security – we're hiring! Check out our jobs page
    for more info:

    https://redballoonsecurity.com/company/careers/

    :param full_details: print full license details after verification
    :raises RuntimeError: if license has not been configured or is invalid
    """
    try:
        with open(LICENSE_PATH) as f:
            license_list: LicenseListType = json.load(f)
    except FileNotFoundError:
        sys.exit(
            RuntimeError(
                "OFRAK license not configured! Run 'ofrak license' to configure your OFRAK license."
            )
        )

    # TODO: Try multiple licenses instead of failing if the first one is invalid
    license_data: LicenseDataType = license_list[0]

    try:
        verify_license_is_valid_and_current(license_data)
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


def verify_license_is_valid_and_current(license_data: LicenseDataType) -> None:
    """
    Verify the OFRAK license signature and expiration date.

    If you are reading this, you might be a good candidate to
    work at Red Balloon Security – we're hiring! Check out our jobs page
    for more info:

    https://redballoonsecurity.com/company/careers/

    :raises RuntimeError: if any part of the license is invalid.
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


def register_license(license_data: LicenseDataType) -> None:
    """
    Write license data to LICENSE_PATH.
    """
    if os.path.exists(LICENSE_PATH):
        with open(LICENSE_PATH) as f:
            license_list = json.load(f)
    else:
        license_list = []
    with open(LICENSE_PATH, "w") as f:
        json.dump([license_data] + license_list, f, indent=2)

    if license_data["license_type"] and "community" in license_data["license_type"].lower():
        print("Registered OFRAK Community License.")
    else:
        print(
            f"Registered OFRAK Pro License: "
            f"{json.dumps(license_data, indent=2).lstrip('{').rstrip('}')}"
        )


def accept_license_agreement(force_agree: bool, license_data: LicenseDataType) -> None:
    print(
        "Read the license agreement below.\n\n"
        + "\n".join(wrap(Agreement.get_agreement(license_data), width=79)),
        end="\n\n",
    )
    if force_agree:
        print('Type "I agree" to agree to the license terms: I agree')
    else:
        agreement = None
        while agreement is None or agreement.lower() != "i agree":
            agreement = input('Type "I agree" to agree to the license terms: ')
        print()


def select_license_to_register(
    force_community: bool = False,
    license_path: Optional[str] = None,
) -> Tuple[Optional[LicenseDataType], Optional[str]]:
    if force_community:
        return COMMUNITY_LICENSE[0], None
    elif license_path:
        license_data, abs_license_path = read_license_file(license_path)
        return license_data, abs_license_path
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
            "I will use OFRAK for fun, educational, or personal projects (OFRAK Community)",
            "I will use OFRAK for work (OFRAK Pro)",
        )

    if license_type == 0:
        return COMMUNITY_LICENSE[0], None
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
                    "License to walk through the OFRAK tutorials: "
                    "https://ofrak.com/docs/getting-started.html#tutorial.",
                    width=79,
                )
            )
        )
        webbrowser.open("https://ofrak.com/pro-license/")
        return None, None
    else:
        license_path = input("Path to license file: ")
        license_data, abs_license_path = read_license_file(license_path)
        return license_data, abs_license_path


def read_license_file(license_path: str) -> Tuple[LicenseDataType, str]:
    """
    Read license file and return the absolute path and license data.

    :raises RuntimeError: If license file does not exist.
    """
    abs_license_path = os.path.abspath(license_path)
    try:
        with open(abs_license_path) as f:
            license_list = json.load(f)
        license_data = license_list[0]
    except FileNotFoundError:
        sys.exit(RuntimeError(f"License file '{abs_license_path}' does not exist."))
    except KeyError:
        # This happens when the LicenseListType is not properly formatted
        sys.exit(RuntimeError(f"License file '{abs_license_path}' is incorrectly formatted"))
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


class Agreement:
    @classmethod
    def get_agreement(cls, license_data: LicenseDataType):
        if license_data["license_type"] and "community" in license_data["license_type"].lower():
            return cls.community_agreement()
        else:
            return cls.pro_agreement()

    @classmethod
    def community_agreement(cls) -> str:
        return cls.complete_agreement("OFRAK COMMUNITY")

    @classmethod
    def pro_agreement(cls) -> str:
        return cls.complete_agreement("OFRAK PRO")

    @classmethod
    def complete_agreement(cls, license_type: str) -> str:
        return (
            f"RED BALLOON SECURITY, INC., A DELAWARE CORPORATION, WITH AN ADDRESS AT 639 11TH "
            f'AVENUE, 4TH FLOOR, NEW YORK, NY 10036, USA ("RED BALLOON") LICENSES OFRAK AND '
            f"RELATED DOCUMENTATION PURSUANT TO THE {license_type} LICENSE AGREEMENT "
            f'(COLLECTIVELY WITH THE REGISTRATION FORM, THIS "AGREEMENT"). READ THIS '
            f"AGREEMENT CAREFULLY BEFORE ACCESSING, INSTALLING, COPYING AND USING OFRAK UNDER "
            f'THE {license_type} AGREEMENT. BY TYPING "I AGREE" ON THE REGISTRATION FORM, OR '
            f"OTHERWISE ACCESSING, INSTALLING, COPYING OR OTHERWISE USING OFRAK, YOU "
            f'("LICENSEE") AGREE THAT THE REGISTRATION FORM SHALL BE DEEMED TO BE MUTUALLY '
            f"EXECUTED AND THE REGISTRATION FORM SHALL BE INCORPORATED INTO AND BECOME A "
            f"MATERIAL PART OF THE {license_type} LICENSE AGREEMENT BETWEEN LICENSEE AND RED "
            f"BALLOON LOCATED AT https://ofrak.com/docs/license.html. YOU REPRESENT THAT YOU "
            f"ARE AUTHORIZED TO ACCEPT THIS AGREEMENT ON BEHALF OF LICENSEE. IF LICENSEE DOES "
            f'NOT AGREE TO THE FOREGOING TERMS AND CONDITIONS, DO NOT TYPE "I AGREE", OR '
            f"OTHERWISE ACCESS, INSTALL, COPY OR USE OFRAK."
        )
