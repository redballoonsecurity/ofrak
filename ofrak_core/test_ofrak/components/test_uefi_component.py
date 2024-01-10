import pytest
import os.path
from dataclasses import dataclass
from typing import Dict
from ofrak.core.uefi import Uefi
from ofrak.core.filesystem import File, FilesystemEntry
from ofrak.resource import Resource
from ofrak import OFRAKContext
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyPattern,
    UnpackAndVerifyTestCase,
)
import test_ofrak.components
from typing import Set


@dataclass
class UefiComponentTestCase(UnpackAndVerifyTestCase[str, bytes]):
    filename: str


UEFI_COMPONENT_TEST_CASE = [
    UefiComponentTestCase(
        "Single text file",
        {
            "2 763BED0D-DE9F-48F5-81F1-3E90E1B1A015/0 SecMain/1 UI section/body.bin": b"S\x00e\x00c\x00M\x00a\x00i\x00n\x00\x00\x00"
        },
        set(),
        "OVMF.rom",
    ),
]


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

    def verify_no_extraneous_descendants(
        self,
        unpacked_set: Set,
        expected_set: Set,
        optional_set: Set,
        info_str: str = f"",
    ):
        pass
