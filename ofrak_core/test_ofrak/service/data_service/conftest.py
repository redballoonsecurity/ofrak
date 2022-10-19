import functools

import pytest

from ofrak.service.data_service import DataService
from ofrak.service.data_service_i import DataServiceInterface
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


DATA_SERVICE_IMPLEMENTATIONS = [functools.partial(DataService)]


@pytest.fixture(params=DATA_SERVICE_IMPLEMENTATIONS, scope="function")
async def data_service(request):
    return request.param()


@pytest.fixture
async def populated_data_service(data_service: DataServiceInterface):
    await data_service.create_root(DATA_0, (b"\x00" * 0x10) + (b"\x10" * 0x8))
    _ = await data_service.create_mapped(DATA_1, DATA_0, Range(0x0, 0x8))
    _ = await data_service.create_mapped(DATA_2, DATA_0, Range(0x8, 0x10))
    _ = await data_service.create_mapped(DATA_3, DATA_2, Range(0x0, 0x4))
    _ = await data_service.create_mapped(DATA_4, DATA_2, Range(0x4, 0x8))

    await data_service.create_mapped(DATA_5, DATA_0, Range(0x10, 0x18))
    return data_service
