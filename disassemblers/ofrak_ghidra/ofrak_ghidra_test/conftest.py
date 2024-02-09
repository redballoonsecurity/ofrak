from ofrak import OFRAKContext
from ofrak.core import Elf
from ofrak.resource import Resource

import ofrak_ghidra
import pytest

from test_ofrak.components.hello_world_elf import hello_elf

pytest_plugins = ["pytest_ofrak.fixtures"]


@pytest.fixture(scope="session")
def hello_world_elf() -> bytes:
    return hello_elf()


@pytest.fixture(autouse=True)
def ghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_ghidra)


@pytest.fixture()
async def hello_world_elf_resource(
    hello_world_elf, ofrak_context: OFRAKContext, test_id: str
) -> Resource:
    resource = await ofrak_context.create_root_resource(
        test_id,
        hello_world_elf,
        tags=(Elf,),
    )
    return resource


@pytest.fixture
def test_id():
    return "TEST_JOB"
