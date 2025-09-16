import pytest
import ofrak_cached_disassembly


pytest_plugins = ["pytest_ofrak.fixtures"]


@pytest.fixture(autouse=True)
def pyghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_cached_disassembly)


@pytest.fixture
def test_id():
    return "TEST_JOB"
