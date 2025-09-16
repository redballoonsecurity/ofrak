import pytest

import ofrak_binary_ninja
from test_ofrak.components.hello_world_elf import hello_elf

pytest_plugins = ["pytest_ofrak.fixtures"]


@pytest.fixture(scope="session")
def hello_world_elf() -> bytes:
    return hello_elf()


@pytest.fixture(autouse=True)
def binary_ninja_components(ofrak_injector):
    ofrak_injector.discover(ofrak_binary_ninja)


@pytest.fixture
def test_id():
    return "TEST_JOB"
