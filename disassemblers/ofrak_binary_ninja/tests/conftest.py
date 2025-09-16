import pytest
import ofrak_binary_ninja

pytest_plugins = ["pytest_ofrak.fixtures"]


@pytest.fixture(autouse=True)
def binary_ninja_components(ofrak_injector):
    ofrak_injector.discover(ofrak_binary_ninja)


@pytest.fixture
def test_id():
    return "TEST_JOB"
