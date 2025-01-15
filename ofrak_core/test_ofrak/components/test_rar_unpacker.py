import os.path
from dataclasses import dataclass
from typing import Dict

import pytest
from ofrak.core.filesystem import File

from ofrak.resource import Resource

from ofrak import OFRAKContext
from ofrak.core.rar import RarArchive, RarUnpacker
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyPattern,
    UnpackAndVerifyTestCase,
)
import test_ofrak.components


@dataclass
class RarUnpackerTestCase(UnpackAndVerifyTestCase[str, bytes]):
    filename: str


RAR_UNPACKER_TEST_CASES = [
    RarUnpackerTestCase("Single text file", {"hello.txt": b"hello world"}, set(), "hello.rar"),
]


@pytest.mark.skipif_missing_deps([RarUnpacker])
class TestRarUnpackAndVerify(UnpackAndVerifyPattern):
    @pytest.fixture(params=RAR_UNPACKER_TEST_CASES, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> RarUnpackerTestCase:
        return request.param

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: RarUnpackerTestCase,
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
        await root_resource.unpack_recursively()

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict[str, bytes]:
        rar_view = await unpacked_root_resource.view_as(RarArchive)
        children = await rar_view.list_dir()
        return {
            name: await child.resource.get_data()
            for name, child in children.items()
            if child.is_file()
        }

    async def verify_descendant(self, unpacked_descendant: bytes, specified_result: bytes):
        assert unpacked_descendant == specified_result
