import pytest

from ofrak.service.resource_service_i import ResourceServiceInterface
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface
from test_ofrak.service.resource_service.test_resource_service import TestResourceService
from test_ofrak.service.resource_service.test_resource_service import (
    resource_service,  # noqa
    tree1_resource_models,  # noqa
    tree2_resource_models,  # noqa
    tree3_resource_models,  # noqa
    basic_populated_resource_service as _basic_populated_resource_service,
    populated_resource_service as _populated_resource_service,
    triple_populated_resource_service as _triple_populated_resource_service,
)


@pytest.fixture
async def basic_populated_resource_service(
    resource_service: ResourceServiceInterface,
    tree1_resource_models,
    serializer: SerializerInterface,
):
    return _reserialize(
        await _basic_populated_resource_service(resource_service, tree1_resource_models), serializer
    )


@pytest.fixture
async def populated_resource_service(
    resource_service: ResourceServiceInterface,
    tree3_resource_models,
    serializer: SerializerInterface,
):
    return _reserialize(
        await _populated_resource_service(resource_service, tree3_resource_models), serializer
    )


@pytest.fixture
async def triple_populated_resource_service(
    resource_service: ResourceServiceInterface,
    tree1_resource_models,
    tree2_resource_models,
    tree3_resource_models,
    serializer: SerializerInterface,
):
    return _reserialize(
        await _triple_populated_resource_service(
            resource_service, tree1_resource_models, tree2_resource_models, tree3_resource_models
        ),
        serializer,
    )


class TestDeserializedSerializedResourceService(TestResourceService):
    pass


def _reserialize(
    resource_service: ResourceServiceInterface, serializer: SerializerInterface
) -> ResourceServiceInterface:
    serialized = serializer.obj_to_pjson(resource_service, ResourceServiceInterface)
    return serializer.pjson_to_obj(serialized, ResourceServiceInterface)
