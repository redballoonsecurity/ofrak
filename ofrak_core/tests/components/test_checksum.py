import os

import psutil
import pytest
from dataclasses import dataclass

from ofrak import OFRAKContext
from ofrak.core.checksum import Md5Attributes, Sha256Attributes

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))


@dataclass
class ChecksumTestCase:
    filename: str
    checksum: str


SHA256_TEST_CASES = [
    ChecksumTestCase(
        "arm_reloc_relocated.elf",
        "8e90534b3c5bd4d62d1f4e60209959f2f01856393e99d10e1f614e4678e16449",
    ),
    ChecksumTestCase(
        "hello.out", "26a6a8a34e127158f5aa13993deb053c40b6ebae1d7ebe8a5acdbf53cf06a92b"
    ),
    ChecksumTestCase(
        "hello.rar", "3f05886d6a27bc9c93cd0b8ad7a3583997e69647a310e28bdb19b29fbe276199"
    ),
    ChecksumTestCase(
        "imx7d-sdb.dtb", "799a6c9ad4c721ee10e9ef5c0dfd402a468e1d271fd63301569f206d8bae90b2"
    ),
    ChecksumTestCase(
        "simple_arm_gcc.o.elf",
        "79d1f8e99626f1d0cef162501413c585a652ca093d055d61a7a4a29ba3f7fed8",
    ),
    ChecksumTestCase(
        "testtar.tar", "760200dda3cfdff2cd31d8ab6c806794f3770faa465e7eae00a1cb3a2fbcbe3a"
    ),
    ChecksumTestCase("uimage", "6ccc12a19b7239cffbe729313fb84d6b460e7fce19c2364f5c2314d78c801ff0"),
    ChecksumTestCase(
        "uimage_lzma", "16e017a34a3f7d013f6e85019016f158fb85ea9494f82b99126feedca64e1b56"
    ),
    ChecksumTestCase(
        "uimage_multi", "7466e7ef8eca723f2a59826d6579d19f57425120f6906e61112e4701f9b72f0e"
    ),
    ChecksumTestCase(
        "uimage_nested", "963e118187e8d2f67bc897da6c3b1b4998ecc4c27ca86b12397a16a6496ab7c0"
    ),
    ChecksumTestCase(
        "uimage_zimage", "d559132a20840f1b47aad5bb7d89cd6f04a2900827f9fe215bdd48b3fdf05a7b"
    ),
]
MD5_TEST_CASES = [
    ChecksumTestCase("arm_reloc_relocated.elf", "ed69056d3dbca810fa3a3f93db9e8927"),
    ChecksumTestCase("hello.out", "cc2de3c0cd2d0ded7543682c2470fcf0"),
    ChecksumTestCase("hello.rar", "2099ca6806611b17a831b10f7f8f006f"),
    ChecksumTestCase("imx7d-sdb.dtb", "3ddcac2458672d77d65ea0ffcdb24817"),
    ChecksumTestCase("simple_arm_gcc.o.elf", "c79d1bea0398d7a9d0faa1ba68786f5e"),
    ChecksumTestCase("testtar.tar", "8ae56950e87dcadfdef07198b4e157e9"),
    ChecksumTestCase("uimage", "2660a3fdc3135558693f200e9740e11f"),
    ChecksumTestCase("uimage_lzma", "7f8b619a3fe392cfcfdfffbbfd977bdf"),
    ChecksumTestCase("uimage_multi", "fd87b4e86a096b70b19fd008fae0b800"),
    ChecksumTestCase("uimage_nested", "6121505d809ab8049ed45482e637f926"),
    ChecksumTestCase("uimage_zimage", "cee7cce4effe394bd2348d0234ddb1fe"),
]


@pytest.mark.parametrize("test_file", SHA256_TEST_CASES, ids=lambda tc: tc.filename)
async def test_sha256(ofrak_context: OFRAKContext, test_file):
    filepath = os.path.join(ASSETS_DIR, test_file.filename)
    resource = await ofrak_context.create_root_resource_from_file(filepath)
    await resource.analyze_recursively()

    sha256_attributes = resource.get_attributes(Sha256Attributes)
    sha_digest = sha256_attributes.checksum
    assert (
        sha_digest == test_file.checksum
    ), f"SHA256 digests do not match. Got {sha_digest}, expected {test_file.checksum}"


@pytest.mark.parametrize("test_file", MD5_TEST_CASES, ids=lambda tc: tc.filename)
async def test_md5(ofrak_context: OFRAKContext, test_file):
    p = psutil.Process()
    [print(f.path) for f in p.open_files()]
    filepath = os.path.join(ASSETS_DIR, test_file.filename)
    resource = await ofrak_context.create_root_resource_from_file(filepath)
    await resource.analyze_recursively()

    md5_attributes = resource.get_attributes(Md5Attributes)
    md5_digest = md5_attributes.checksum
    assert (
        md5_digest == test_file.checksum
    ), f"MD5 digests do not match. Got {md5_digest}, expected {test_file.checksum}"
