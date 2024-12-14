from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary, BinaryExtendConfig, BinaryExtendModifier
from ofrak.resource import Resource
from pytest_ofrak.patterns.modify import ModifyPattern

TEST_BINARY = b"\x00" * 0x100
CONTENT = b"RBS" * 40


class TestBinaryExtendModify(ModifyPattern):
    expected_tag = GenericBinary

    def create_root_resource(self, ofrak_context: OFRAKContext):
        return ofrak_context.create_root_resource("bin", TEST_BINARY)

    def modify(self, root_resource: Resource) -> None:
        config = BinaryExtendConfig(CONTENT)
        root_resource.run(BinaryExtendModifier, config)

    def verify(self, root_resource: Resource):
        data_len = root_resource.get_data_length()
        assert data_len == len(TEST_BINARY) + len(CONTENT)

        data = root_resource.get_data()
        assert data == TEST_BINARY + CONTENT
