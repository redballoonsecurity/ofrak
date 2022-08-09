import sys
from dataclasses import dataclass

import pytest

from ofrak import OFRAKContext
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource


@dataclass
class MockUnpackerConfig(ComponentConfig):
    field_a: int
    field_b: int


class MockUnpackerRequiresDefault(Unpacker[MockUnpackerConfig]):
    """
    Component fails if the given config does not match a specific config value, which is the
    default.
    """

    targets = (GenericBinary,)
    children = ()

    async def unpack(
        self,
        resource: Resource,
        config: MockUnpackerConfig = MockUnpackerConfig(3, 6),
    ) -> None:
        assert config is not None

        assert config.field_a == 3
        assert config.field_b == 6


class MockUnpackerWithDefaultRequiresPopulated(Unpacker[MockUnpackerConfig]):
    """
    Component fails if the given config does not match a specific config value, which is not the
    default. The valid config must be successfully passed, and the default not used, for it to
    not fail.
    """

    targets = (GenericBinary,)
    children = ()

    async def unpack(
        self, resource: Resource, config: MockUnpackerConfig = MockUnpackerConfig(3, 6)
    ) -> None:
        assert config is not None

        assert config.field_a == 4
        assert config.field_b == 8


class MockUnpackerModifiesDefaultArgument(Unpacker[MockUnpackerConfig]):
    """
    Component modifies the config after checking its field. When run twice in a row,
    this would fail if the default config value is modifiable within the component body.
    """

    targets = (GenericBinary,)
    children = ()

    async def unpack(
        self, resource: Resource, config: MockUnpackerConfig = MockUnpackerConfig(3, 6)
    ) -> None:
        assert config is not None

        assert config.field_a == 3
        assert config.field_b == 6

        config.field_a = 1
        config.field_b = 2


@pytest.fixture(autouse=True)
def mock_unpacker_component(ofrak):
    ofrak.injector.discover(sys.modules[__name__])


async def test_unpacker_with_default(ofrak_context: OFRAKContext):
    resource_1 = await ofrak_context.create_root_resource("test resource 1", b"", (GenericBinary,))
    # Will fail if the default config is not provided to unpack
    await resource_1.run(MockUnpackerRequiresDefault)

    resource_2 = await ofrak_context.create_root_resource("test resource 2", b"", (GenericBinary,))
    # Will fail if the default config is provided to unpack
    await resource_2.run(MockUnpackerWithDefaultRequiresPopulated, MockUnpackerConfig(4, 8))

    await resource_1.run(MockUnpackerModifiesDefaultArgument)
    await resource_2.run(MockUnpackerModifiesDefaultArgument)
