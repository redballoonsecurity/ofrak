import pytest
import ofrak_pyghidra


pytest_plugins = ["pytest_ofrak.fixtures", "pytest_ofrak.elf.fixtures"]


@pytest.fixture(autouse=True)
def pyghidra_components(ofrak_injector):
    ofrak_injector.discover(ofrak_pyghidra)


@pytest.fixture
def test_id():
    return "TEST_JOB"
