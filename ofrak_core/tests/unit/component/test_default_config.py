import pytest

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary
from . import mock_component
from .mock_component import (
    MockUnpackerConfig,
    MockUnpackerRequiresDefault,
    MockUnpackerWithDefaultRequiresPopulated,
    MockUnpackerModifiesDefaultArgument,
)

"""
This module tests the default configuration behavior for unpackers.

Requirements Mapping:
- REQ1.5: As an OFRAK user, I want to programmatically invoke a specific unpacker on a specific binary so that I can control which unpackers run.
  - test_unpacker_with_default: Verifies that unpackers can be invoked with default configurations and that default arguments are properly handled
"""


@pytest.fixture(autouse=True)
def mock_unpacker_component(ofrak):
    ofrak.discover(mock_component)


async def test_unpacker_with_default(ofrak_context: OFRAKContext):
    """
    Tests the behavior of unpackers with default configurations (REQ1.5).

    This test verifies that:
    - Unpackers requiring default configs can be invoked without explicit configuration
    - Unpackers with default arguments properly handle both default and explicit configurations
    """
    resource_1 = await ofrak_context.create_root_resource("test resource 1", b"", (GenericBinary,))
    # Will fail if the default config is not provided to unpack
    await resource_1.run(MockUnpackerRequiresDefault)

    resource_2 = await ofrak_context.create_root_resource("test resource 2", b"", (GenericBinary,))
    # Will fail if the default config is provided to unpack
    await resource_2.run(MockUnpackerWithDefaultRequiresPopulated, MockUnpackerConfig(4, 8))

    await resource_1.run(MockUnpackerModifiesDefaultArgument)
    await resource_2.run(MockUnpackerModifiesDefaultArgument)
