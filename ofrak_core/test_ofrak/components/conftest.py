import pytest

pytest_plugins = ["pytest_ofrak.fixtures", "pytest_ofrak.elf.fixtures"]


@pytest.fixture
def test_id():
    return "TEST_JOB"
