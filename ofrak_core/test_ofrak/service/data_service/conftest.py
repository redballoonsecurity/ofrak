import functools

import ofrak.service.serialization
import pytest
from ofrak.ofrak_context import OFRAK

from ofrak.service.data_service import DataService
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.serialization.pjson import PJSONSerializationService
from ofrak_type.range import Range

DATA_0 = b"\x00"
DATA_1 = b"\x01"
DATA_2 = b"\x02"
DATA_3 = b"\x03"
DATA_4 = b"\x04"
DATA_5 = b"\x05"
DATA_6 = b"\x06"
DATA_7 = b"\x07"
DATA_8 = b"\x08"

DATA_TEST_0 = b"\x01\x00"
DATA_TEST_1 = b"\x01\x01"


async def _serialize_deserialize_data_service(data_service: DataService):
    o = OFRAK()
    o.injector.discover(ofrak.service.serialization)
    o.injector.bind_factory(PJSONSerializationService)

    serializer = await o.injector.get_instance(PJSONSerializationService)

    serialized_data_service = serializer.to_pjson(data_service, DataService)
    deserialized_data_service = serializer.from_pjson(serialized_data_service, DataService)

    return deserialized_data_service


DATA_SERVICE_IMPLEMENTATIONS = [
    ("DataService", functools.partial(DataService), None),
    (
        "de/serialized DataService",
        functools.partial(DataService),
        _serialize_deserialize_data_service,
    ),
]


@pytest.fixture(params=DATA_SERVICE_IMPLEMENTATIONS, ids=lambda r: r[0], scope="function")
async def data_service(request):
    _, data_service_factory, postprocessing = request.param
    data_service = data_service_factory()
    await populate_data_service(data_service)
    if postprocessing:
        data_service = await postprocessing(data_service)
    return data_service


@pytest.fixture
async def populated_data_service(data_service: DataServiceInterface):
    return data_service


async def populate_data_service(data_service: DataServiceInterface):
    """
    DATA_0 (0x0, 0x18)  | [-----------------------)
    DATA_1 (0x0, 0x8)   | [-------)
    DATA_2 (0x8, 0x10)  |         [-------)
    DATA_3 (8x0, 0xC)   |         [---)
    DATA_4 (0xC, 0x10)  |             [---)
    DATA_5 (0x10, 0x18) |                 [-------)
    """
    await data_service.create_root(DATA_0, (b"\x00" * 0x10) + (b"\x10" * 0x8))
    _ = await data_service.create_mapped(DATA_1, DATA_0, Range(0x0, 0x8))
    _ = await data_service.create_mapped(DATA_2, DATA_0, Range(0x8, 0x10))
    _ = await data_service.create_mapped(DATA_3, DATA_2, Range(0x0, 0x4))
    _ = await data_service.create_mapped(DATA_4, DATA_2, Range(0x4, 0x8))

    await data_service.create_mapped(DATA_5, DATA_0, Range(0x10, 0x18))
