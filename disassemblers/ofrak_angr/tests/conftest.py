import pytest

import ofrak_angr

pytest_plugins = ["pytest_ofrak.fixtures", "pytest_ofrak.elf.fixtures"]


@pytest.fixture(autouse=True)
def angr_components(ofrak_injector):
    ofrak_injector.discover(ofrak_angr)


@pytest.fixture
def test_id():
    return "TEST_JOB"
