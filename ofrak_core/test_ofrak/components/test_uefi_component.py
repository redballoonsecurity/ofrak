import pytest
import os.path
from dataclasses import dataclass
from typing import Dict
from ofrak.core.uefi import Uefi, UefiUnpacker
from ofrak.core.filesystem import File, FilesystemEntry
from ofrak.resource import Resource
from ofrak import OFRAKContext
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyPattern,
    UnpackAndVerifyTestCase,
)
from pytest_ofrak.mark import requires_deps_of
import test_ofrak.components
from typing import Set


@dataclass
class UefiComponentTestCase(UnpackAndVerifyTestCase[str, bytes]):
    filename: str


UEFI_COMPONENT_TEST_CASE = [
    UefiComponentTestCase(
        "Single text file",
        {
            "2 763BED0D-DE9F-48F5-81F1-3E90E1B1A015/0 SecMain/1 UI section/body.bin": b"S\x00e\x00c\x00M\x00a\x00i\x00n\x00\x00\x00",
            "1 48DB5E17-707C-472D-91CD-1613E7EF51B0/0 9E21FD93-9C72-4C15-8C4B-E77F1DB2D792/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/1 Volume image section/0 6938079B-B503-4E3D-9D24-B28337A25806/0 PEI apriori file/0 Raw section/body.bin": b"O\xda:\x9bV\xae$L\x8d\xea\xf0;uX\xaeP",
            "1 48DB5E17-707C-472D-91CD-1613E7EF51B0/0 9E21FD93-9C72-4C15-8C4B-E77F1DB2D792/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/1 Volume image section/0 6938079B-B503-4E3D-9D24-B28337A25806/14 CpuMpPei/2 PE32 image section/header.bin": b"\x84\x85\x00\x10",
            "1 48DB5E17-707C-472D-91CD-1613E7EF51B0/0 9E21FD93-9C72-4C15-8C4B-E77F1DB2D792/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/3 Volume image section/0 7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1/6 SecurityStubDxe/2 UI section/body.bin": b"S\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00S\x00t\x00u\x00b\x00D\x00x\x00e\x00\x00\x00",
            "1 48DB5E17-707C-472D-91CD-1613E7EF51B0/0 9E21FD93-9C72-4C15-8C4B-E77F1DB2D792/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/2 Raw section/info.txt": b"Type: Section\nSubtype: Raw\nFixed: No\nOffset: E0098h\nType: 19h\nFull size: Ch (12)\nHeader size: 4h (4)\nBody size: 8h (8)\n",
            "0 FFF12B8D-7696-4C8B-A985-2747075B4F50/2 FTW store/body.bin": b"\xff" * 4064,
        },
        set(),
        "OVMF.rom",
    ),
]


@requires_deps_of(UefiUnpacker)
class TestUefiComponent(UnpackAndVerifyPattern):
    @pytest.fixture(params=UEFI_COMPONENT_TEST_CASE, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> UnpackAndVerifyTestCase:
        return request.param

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: UnpackAndVerifyTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(
            test_ofrak.components.ASSETS_DIR, unpack_verify_test_case.filename
        )
        with open(asset_path, "rb") as f:
            data = f.read()
        return await ofrak_context.create_root_resource(test_id, data, tags=(File,))

    async def unpack(self, root_resource: Resource):
        root_resource.add_tag(Uefi)
        await root_resource.save()
        await root_resource.unpack_recursively()

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict:
        result = {
            await (
                await descendent.view_as(FilesystemEntry)
            ).get_path(): await descendent.get_data()
            for descendent in await unpacked_root_resource.get_descendants()
        }
        return result

    async def verify_descendant(self, unpacked_descendant: bytes, specified_result: bytes):
        assert unpacked_descendant == specified_result

    # This function is overwritten to do nothing since we don't want to check for extraneous descendents on OVMF.rom
    def verify_no_extraneous_descendants(
        self,
        unpacked_set: Set,
        expected_set: Set,
        optional_set: Set,
        info_str: str = f"",
    ):
        pass
