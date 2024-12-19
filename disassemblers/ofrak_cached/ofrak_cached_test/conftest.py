import pytest
import ofrak_capstone
import ofrak_cached

from test_ofrak.components.hello_world_elf import hello_elf

pytest_plugins = ["pytest_ofrak.fixtures"]


@pytest.fixture(scope="session")
def hello_world_elf() -> bytes:
    return hello_elf()


@pytest.fixture(autouse=True)
def pyghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_cached)


@pytest.fixture
def test_id():
    return "TEST_JOB"
