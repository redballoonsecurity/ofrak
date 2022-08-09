from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak.core.raw import RawExtendModifier, RawExtendConfig
from pytest_ofrak.patterns.modify import ModifyPattern

TEST_BINARY = b"\x00" * 0x100
CONTENT = b"RBS" * 40


class TestRawExtendModify(ModifyPattern):
    expected_tag = GenericBinary

    async def create_root_resource(self, ofrak_context: OFRAKContext):
        return await ofrak_context.create_root_resource("bin", TEST_BINARY)

    async def modify(self, root_resource: Resource) -> None:
        config = RawExtendConfig(CONTENT)
        await root_resource.run(RawExtendModifier, config)

    async def verify(self, root_resource: Resource):
        data_len = await root_resource.get_data_length()
        assert data_len == len(TEST_BINARY) + len(CONTENT)

        data = await root_resource.get_data()
        assert data == TEST_BINARY + CONTENT
