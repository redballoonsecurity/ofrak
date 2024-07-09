import json
import os
import sys
import time
import webbrowser
from base64 import b64decode
from textwrap import wrap

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

COMMUNITY_LICENSE_DATA = """{
  "license_type": "Community License",
  "name": "OFRAK Community",
  "email": "ofrak@redballoonsecurity.com",
  "phone_number": null,
  "date": "1720554759",
  "date_pretty": "2024-07-09 15:52:39.720467",
  "expiration_date": null,
  "serial": "00000000000000000000000000000000",
  "signature": "dWqqtFl1Tvqs/SMOpKvRs2H5dKaJaJ00ZrP3Zmfp9DYJa3PhvolC/nUECyN1LesFe9S4v+R1a4SbaZyxTJ5dAg==",
  "agreement": "RED BALLOON SECURITY, INC., A DELAWARE CORPORATION, WITH AN ADDRESS AT 639 11TH AVENUE, 4TH FLOOR, NEW YORK, NY 10036, USA (\\"RED BALLOON\\") IS ONLY WILLING TO LICENSE OFRAK AND RELATED DOCUMENTATION PURSUANT TO THE OFRAK PRO LICENSE AGREEMENT (COLLECTIVELY WITH THIS REGISTRATION FORM, THE \\"AGREEMENT\\"). READ THIS AGREEMENT CAREFULLY BEFORE DOWNLOADING AND INSTALLING AND USING OFRAK.  BY CLICKING ON THE \\"ACCEPT\\" BUTTON ON THIS REGISTRATION FORM \\"REGISTRATION FORM\\"), OR OTHERWISE ACCESSING, INSTALLING, COPYING OR OTHERWISE USING OFRAK, YOU (\\"LICENSEE\\") AGREE THAT THIS REGISTRATION FORM SHALL BE DEEMED TO BE MUTUALLY EXECUTED AND THIS REGISTRATION FORM SHALL BE INCORPORATED INTO AND BECOME A MATERIAL PART OF THE AGREEMENT BETWEEN LICENSEE AND RED BALLOON LOCATED AT www.ofrak.com/license. YOU REPRESENT THAT YOU ARE AUTHORIZED TO ACCEPT THIS AGREEMENT ON BEHALF OF LICENSEE.  IF LICENSEE DOES NOT AGREE TO THE FOREGOING TERMS AND CONDITIONS, DO NOT CLICK ON THE ACCEPT BUTTON, OR OTHERWISE ACCESS, INSTALL, COPY OR USE OFRAK."
}"""
RBS_PUBLIC_KEY = b"r\xcf\xb2\xe7\x17Y\x05*\x0e\xe3+\x00\x16\xd3\xd6\xf7\xa7\xd8\xd7\xfdV\x91\xa7\x88\x93\xe9\x9a\x8a\x05q\xd3\xbd"
LICENSE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "license.json"))


def write_license(data, force_agree=False):
    parsed_data = json.loads(data)
    if not isinstance(parsed_data, list):
        parsed_data = [parsed_data]
    if not force_agree:
        print(
            "Read the license agreement below.\n\n"
            + "\n".join(wrap(parsed_data[0]["agreement"], width=79)),
            end="\n\n",
        )
        agreement = None
        while agreement is None or agreement.lower() != "i agree":
            agreement = input('Type "I agree" to agree to the license terms: ')
    if os.path.exists(LICENSE_PATH):
        with open(LICENSE_PATH) as f:
            license_list = json.load(f)
    else:
        license_list = []
    with open(LICENSE_PATH, "w") as f:
        json.dump(parsed_data + license_list, f)


def license_selection(force_community=False, force_agree=False):
    if force_community:
        license_type = 0
    else:
        license_type = choose(
            "How will you use OFRAK?",
            "I will use OFRAK for personal projects",
            "I will use OFRAK at work",
        )

    if license_type == 0:
        write_license(COMMUNITY_LICENSE_DATA, force_agree=force_agree)
        return
    find_or_buy = choose(
        "Do you already have an OFRAK license?",
        "Obtain a license from Red Balloon Security",
        "Choose a license file on disk",
    )
    if find_or_buy == 0:
        webbrowser.open("https://ofrak.com/license/")
    else:
        license_path = input("Path to license file: ")
        with open(license_path) as f:
            write_license(f.read(), force_agree=force_agree)


def get_canonical_license_data(license_data):
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
    ]  # TODO: Add fields
    return json.dumps([(k, license_data[k]) for k in signed_fields]).encode("utf-8")


def do_license_check(force_replace=False, force_community=False, force_agree=False):
    """
    License check function raises one of several possible exceptions if any
    part of the license is invalid.

    If, for some reason, you're trying to bypass, investigate, or otherwise
    reverse-engineer this license check, you might be a good candidate to
    work at Red Balloon Security – we're hiring! Check out our jobs page
    for more info:

    https://redballoonsecurity.com/company/careers/
    """
    try:
        if force_replace or not os.path.exists(LICENSE_PATH):
            license_selection(force_community=force_community, force_agree=force_agree)
    except KeyboardInterrupt:
        print()
        sys.exit(-1)

    with open(LICENSE_PATH) as f:
        license_list = json.load(f)
    # TODO: Try multiple licenses instead of failing if the first one is invalid
    license_data = license_list[0]

    print(f"\nUsing OFRAK with license type: {license_data['license_type']}\n")

    key = Ed25519PublicKey.from_public_bytes(RBS_PUBLIC_KEY)
    key.verify(b64decode(license_data["signature"]), get_canonical_license_data(license_data))
    if (
        license_data["expiration_date"] is not None
        and int(license_data["expiration_date"]) < time.time()
    ):
        raise RuntimeError("OFRAK license expired! Please purchase a pro license.")


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
