import logging

import pytest

from ofrak.service.id_service_sequential import SequentialIDService
from ofrak import OFRAK

from synthol.injector import DependencyInjector


@pytest.fixture
def ofrak_injector():
    return DependencyInjector()


@pytest.fixture
def ofrak_id_service():
    return SequentialIDService()


@pytest.fixture
def ofrak(ofrak_injector, ofrak_id_service):
    ofrak = OFRAK(logging.INFO)
    ofrak.injector = ofrak_injector
    ofrak.set_id_service(ofrak_id_service)

    return ofrak


@pytest.fixture
async def ofrak_context(ofrak):
    context = await ofrak.create_ofrak_context()
    yield context
    await context.shutdown_context()
