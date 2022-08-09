import pytest

import ofrak_components

pytest_plugins = ["pytest_ofrak.fixtures"]


@pytest.fixture(autouse=True)
def ofrak_components_module(ofrak_injector):
    ofrak_components.bind_dependencies(ofrak_injector)


@pytest.fixture
def test_id():
    return "TEST_JOB"
