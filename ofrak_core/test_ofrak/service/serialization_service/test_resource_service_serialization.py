import pytest

from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak.service.serialization.service_i import SerializationServiceInterface
from test_ofrak.service.resource_service.test_resource_service import TestResourceService


@pytest.fixture
async def basic_populated_resource_service(
    basic_populated_resource_service,
    serializer: SerializationServiceInterface,
):
    return _reserialize(basic_populated_resource_service, serializer)


@pytest.fixture
async def populated_resource_service(
    populated_resource_service,
    serializer: SerializationServiceInterface,
):
    return _reserialize(populated_resource_service, serializer)


@pytest.fixture
async def triple_populated_resource_service(
    triple_populated_resource_service,
    serializer: SerializationServiceInterface,
):
    return _reserialize(
        triple_populated_resource_service,
        serializer,
    )


class TestDeserializedSerializedResourceService(TestResourceService):
    pass


def _reserialize(
    resource_service: ResourceServiceInterface, serializer: SerializationServiceInterface
) -> ResourceServiceInterface:
    serialized = serializer.to_json(resource_service, ResourceServiceInterface)
    return serializer.from_json(serialized, ResourceServiceInterface)
