import asyncio

import pytest

from ofrak import OFRAK
from ofrak.service.serialization.pjson import PJSONSerializationService
from ofrak.service.serialization.service_i import SerializationServiceInterface
from ofrak.service.serialization.stashed_pjson import StashedPJSONSerializationService


@pytest.fixture(scope="session")
def event_loop():
    """
    Necessary to use scope="session" with async fixtures, see
    <https://stackoverflow.com/a/56238383>
    """
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def ofrak() -> OFRAK:
    """
    Only create an OFRAK instance once per session for performance
    """
    import ofrak.service.serialization

    o = OFRAK()
    o.injector.discover(ofrak.service.serialization)
    o.injector.bind_factory(PJSONSerializationService)
    return o


@pytest.fixture(scope="session")
async def serializer(ofrak) -> PJSONSerializationService:
    return await ofrak.injector.get_instance(PJSONSerializationService)


@pytest.fixture(scope="session")
async def stashed_serializer(ofrak) -> StashedPJSONSerializationService:
    return await ofrak.injector.get_instance(StashedPJSONSerializationService)


@pytest.fixture(scope="session", params=[0, 1])
def _test_serialize_deserialize(request, serializer, stashed_serializer):
    """
    This fixture will be invoked twice for each test, one time with the `serializer` fixture and one
     time with `stashed_serializer`.

    It returns a function of an object and type hint that tests serialization and deserialization
    using the above-mentioned serializer.
    """
    serializer_: SerializationServiceInterface = [serializer, stashed_serializer][request.param]

    def _inner(obj, type_hint):
        assert serializer_.from_pjson(serializer_.to_pjson(obj, type_hint), type_hint) == obj
        assert serializer_.from_json(serializer_.to_json(obj, type_hint), type_hint) == obj

    return _inner
