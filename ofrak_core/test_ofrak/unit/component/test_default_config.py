import pytest

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary
from test_ofrak.unit.component import mock_component
from test_ofrak.unit.component.mock_component import (
    MockUnpackerConfig,
    MockUnpackerRequiresDefault,
    MockUnpackerWithDefaultRequiresPopulated,
    MockUnpackerModifiesDefaultArgument,
)


@pytest.fixture(autouse=True)
def mock_unpacker_component(ofrak):
    ofrak.injector.discover(mock_component)


async def test_unpacker_with_default(ofrak_context: OFRAKContext):
    resource_1 = await ofrak_context.create_root_resource("test resource 1", b"", (GenericBinary,))
    # Will fail if the default config is not provided to unpack
    await resource_1.run(MockUnpackerRequiresDefault)

    resource_2 = await ofrak_context.create_root_resource("test resource 2", b"", (GenericBinary,))
    # Will fail if the default config is provided to unpack
    await resource_2.run(MockUnpackerWithDefaultRequiresPopulated, MockUnpackerConfig(4, 8))

    await resource_1.run(MockUnpackerModifiesDefaultArgument)
    await resource_2.run(MockUnpackerModifiesDefaultArgument)
