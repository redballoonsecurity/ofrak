"""
This module tests binary extension functionality in OFRAK.

Requirements Mapping:
- REQ3.2:
  - TestBinaryExtendModify: Tests the ability to extend a binary resource with additional content
"""

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary, BinaryExtendConfig, BinaryExtendModifier
from ofrak.resource import Resource
from pytest_ofrak.patterns.modify import ModifyPattern

TEST_BINARY = b"\x00" * 0x100
CONTENT = b"RBS" * 40


class TestBinaryExtendModify(ModifyPattern):
    """Tests the ability to extend a binary resource with additional content (REQ3.2).

    This test verifies that:
    - A binary resource can be extended with additional bytes
    - The extended data is correctly appended to the original binary
    - The final resource size matches the expected extended size
    """

    expected_tag = GenericBinary

    async def create_root_resource(self, ofrak_context: OFRAKContext):
        return await ofrak_context.create_root_resource("bin", TEST_BINARY)

    async def modify(self, root_resource: Resource) -> None:
        config = BinaryExtendConfig(CONTENT)
        await root_resource.run(BinaryExtendModifier, config)

    async def verify(self, root_resource: Resource):
        data_len = await root_resource.get_data_length()
        assert data_len == len(TEST_BINARY) + len(CONTENT)

        data = await root_resource.get_data()
        assert data == TEST_BINARY + CONTENT
