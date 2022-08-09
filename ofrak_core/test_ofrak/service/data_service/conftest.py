import pytest

from ofrak_type.range import Range
from ofrak.service.data_service import DataService
from test_ofrak.service.data_service.data_service_test import (
    DATA_0,
    DATA_1,
    DATA_2,
    DATA_3,
    DATA_4,
    DATA_5,
)


@pytest.fixture
async def populated_data_service():
    """
    Create and return the following state:
    DATA_0 (0x0, 0x18)
     |
     +- DATA_1 (0x0, 0x8)
     +- DATA_2 (0x8, 0x10)
     |   |
     |   +- DATA_3 (0x0, 0x4)
     |   +- DATA_4 (0x4, 0x8)
     +- DATA_5 (0x10, 0x18)
    """
    data_service = DataService()
    await data_service.create(DATA_0, b"\x00" * 0x18)
    await data_service.create_mapped(DATA_1, DATA_0, Range(0x0, 0x8))

    await data_service.create_mapped(DATA_2, DATA_0, Range(0x8, 0x10))
    await data_service.create_mapped(DATA_3, DATA_2, Range(0x0, 0x4))
    await data_service.create_mapped(DATA_4, DATA_2, Range(0x4, 0x8))

    await data_service.create_mapped(DATA_5, DATA_0, Range(0x10, 0x18))
    return data_service
