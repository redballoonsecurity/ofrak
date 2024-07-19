"""
Tests for the DataSummaryAnalyzer that expect ofrak_gpu to be installed go here. See fixtures.

For example, tests that ensure entropy_gpu is used before entropy_py/c would go here. 

Tests for the functions inside ofrak_gpu themselves do NOT go here. The tests in this file must
pass regardless of the presence of ofrak_gpu. Tests for entropy_gpu and anything else in ofrak_gpu
must go in ofrak_gpu's testing directory, not in ofrak_core.

Tests for behavior in the absense of ofrak_gpu, eg for entropy_py/c, don't go here; see 
test_entropy_component.py and its fixtures.
"""
import sys
import importlib
import os.path
import pytest
from ofrak import OFRAKContext
import test_ofrak.components
from typing import Any

DEFAULT_WINDOW_SIZE = 256  # This should match what DataSummaryAnalyzer uses as its window size


@pytest.fixture(autouse=True)
def reload_entropy():
    """
    A fixture, automatically used before each test case, that triggers a module reload for entropy.
    This process is required for test that don't use mock_ofrak_gpu to import entropy correctly.
    """
    import ofrak.core.entropy as entropy_module

    importlib.reload(entropy_module)


def mock_entropy_gpu(
    data: bytes, window_size: int = DEFAULT_WINDOW_SIZE, log_percent: Any = None
) -> bytes:
    """
    A mock function that matches the function signature of ofrak_gpu.entropy_gpu.entropy_gpu().
    When the mock_ofrak_gpu fixture is used, from ofrak_gpu.entropy_gpu import entropy_gpu will
    always import this function, even if the ofrak_gpu module is installed in the test environment.

    This produces intentionally incorrect data of the same format as the C, Python, and GPU-bound
    implementations of Shannon entropy, so it is clear when the obtained result came from this
    function. This lets us assert that DataSummaryAnalyzer will use ofrak_gpu before core.entropy.

    :param data: The raw data to return the mock entropy of
    :type data: bytes
    :param window_size: The sliding window for entropy calculation's size. Used to mock results
    :type window_size: int
    :param log_percent: Unused
    :type log_percent: Any
    :return: Bytes meant to be easily distringuishable from the results of a real entropy function
    :rtype: bytes
    """
    return bytes(i % 256 for i in range(len(data) - window_size))


@pytest.fixture
def mock_ofrak_gpu(monkeypatch):
    """
    A fixture used to create a fake ofrak_gpu.entropy_gpu module, overwriting it if it exists.
    This ensures that from ofrak_gpu.entropy_gpu import entropy_gpu will import mock_entropy_gpu.
    Using this fixture will guarantee the imports in ofrak.core.entropy will succeed and import
    the same function, whether or not the test environment has ofrak_gpu installed.
    """
    import ofrak.core.entropy as entropy_module
    import ofrak.core.entropy.entropy as entropy_entropy_module

    mock_gpu_module = type(sys)("ofrak_gpu")
    mock_gpu_module.entropy_gpu = type(sys)("entropy_gpu")
    mock_gpu_module.entropy_gpu.entropy_gpu = mock_entropy_gpu

    monkeypatch.setitem(sys.modules, "ofrak_gpu", mock_gpu_module)
    monkeypatch.setitem(sys.modules, "ofrak_gpu.entropy_gpu", mock_gpu_module.entropy_gpu)

    importlib.reload(entropy_entropy_module)
    importlib.reload(entropy_module)

    yield

    monkeypatch.undo()

    importlib.reload(entropy_module)
    importlib.reload(entropy_entropy_module)


TEST_FILES = [
    "hello.out",
    "arm_reloc_relocated.elf",
    "flash_test_magic.bin",
    "hello.rar",
    "imx7d-sdb.dtb",
    "simple_arm_gcc.o.elf",
]


@pytest.mark.parametrize(
    "test_file_path",
    [os.path.join(test_ofrak.components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
@pytest.mark.usefixtures("mock_ofrak_gpu")
async def test_analyzer_gpu(ofrak_context: OFRAKContext, test_file_path):
    """
    Ensures that, when the ofrak_gpu module is installed, the DataSummaryAnalyzer will use the
    ofrak_gpu.entropy_gpu.entropy_gpu() function for its entropy calculations, not the Python
    or C implementations.

    This is done using the mock_ofrak_gpu fixture. Whether or not the ofrak_gpu module is installed
    alongside ofrak_core in the testing environment, this fixture will trick DataSummaryAnalyzer
    into successfully importing mock_entropy_gpu from ofrak_gpu.entropy_gpu.entropy_gpu. Thus,
    by asserting that the computed entropy == entropy_gpu's result == mock_entropy_gpu's result,
    we know DataSummaryAnalyzer will use ofrak_gpu.entropy_gpu, if found, before core.entropy's C.
    """
    # These imports must be done inside the test function, as they must be run *after* the fixture
    from ofrak.core.entropy import DataSummaryAnalyzer, DataSummary
    from ofrak_gpu.entropy_gpu import entropy_gpu

    with open(test_file_path, "rb") as f:
        data = f.read()

    root = await ofrak_context.create_root_resource_from_file(test_file_path)
    await root.run(DataSummaryAnalyzer)
    data_summary = root.get_attributes(DataSummary)
    entropy = data_summary.entropy_samples

    # Asserts that DataSummaryAnalyzer uses ofrak_gpu.entropy_gpu.entropy_gpu = mock_entropy_gpu
    assert entropy == mock_entropy_gpu(data, DEFAULT_WINDOW_SIZE, None)
    assert entropy == entropy_gpu(data, DEFAULT_WINDOW_SIZE, None)
