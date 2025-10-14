"""
This module tests the ID service implementation.
"""

import pytest

from ofrak.service.id_service_i import IDServiceInterface
from ofrak.service.id_service_sequential import SequentialIDService
from ofrak.service.id_service_uuid import UUIDService


@pytest.fixture()
def sequential_id_service():
    return SequentialIDService()


@pytest.fixture()
def uuid_service():
    return UUIDService()


@pytest.fixture(
    params=[
        pytest.lazy_fixture("sequential_id_service"),
        pytest.lazy_fixture("uuid_service"),
    ]
)
def id_service(request) -> IDServiceInterface:
    return request.param


def test_get_id(id_service):
    """
    ID generation produces unique values.

    This test verifies that:
    - Generating two IDs in sequence results in different values
    - Each generated ID is unique within the service instance
    """
    id1 = id_service.generate_id()
    id2 = id_service.generate_id()

    assert id1 != id2


def test_generate_id_from_base(id_service):
    """
    ID generation from base maintains uniqueness and consistency.

    This test verifies that:
    - Different keys with same base produce different IDs
    - Same key with same base reproduces identical IDs
    - Different base/key combinations produce unique IDs
    """
    base_id = id_service.generate_id()
    key1 = "alpha"
    key2 = "beta"

    id1 = id_service.generate_id_from_base(base_id, key1)
    id2 = id_service.generate_id_from_base(base_id, key2)

    assert id1 != id2

    _id1 = id_service.generate_id_from_base(base_id, key1)
    assert _id1 == id1

    _id2 = id_service.generate_id_from_base(base_id, key2)
    assert _id2 == id2

    id3 = id_service.generate_id_from_base(id1, key2)
    assert id3 != id1
    assert id3 != id2
