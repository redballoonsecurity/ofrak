import os
import tempfile

import filelock
import pytest

# Held by every test that uses the Ghidra backend: the backend serves the analysis of one program
# at a time, and starting the analysis of a program stops the analysis server of any other, which
# would break a Ghidra test running in parallel.
GHIDRA_BACKEND_LOCK = os.path.join(tempfile.gettempdir(), "ofrak_ghidra_backend.lock")


@pytest.fixture
def test_id():
    return "TEST_JOB"


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items):
    # With `pytest --dist loadgroup`, run all the tests using the Ghidra backend in the same
    # pytest-xdist worker, one after the other, instead of having workers wait for the lock
    for item in items:
        if "ghidra_backend" in getattr(item, "fixturenames", ()):
            item.add_marker(pytest.mark.xdist_group("ghidra_backend"))


@pytest.fixture
def ghidra_backend():
    """
    The Ghidra backend package, used by one test at a time. Skips the test if it is not installed.
    """
    ofrak_ghidra = pytest.importorskip("ofrak_ghidra")
    with filelock.FileLock(GHIDRA_BACKEND_LOCK):
        yield ofrak_ghidra


@pytest.fixture
async def ghidra_ofrak_context(ofrak, ghidra_backend):
    """
    An OFRAK context with the Ghidra backend.
    """
    ofrak.discover(ghidra_backend)
    context = await ofrak.create_ofrak_context()
    yield context
    await context.shutdown_context()
