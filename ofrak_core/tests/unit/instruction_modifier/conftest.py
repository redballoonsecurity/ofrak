import pytest

import ofrak.core.instruction


@pytest.fixture(autouse=True)
def instruction_dependencies_modules(ofrak_injector):
    ofrak_injector.discover(ofrak.core.instruction)
