# """
# Tests for entropy calculation and the DataSummaryAnalyzer

# For example, tests for the correctness of entropy_py/c, tests that ensure they are used in the
# absence of ofrak_gpu, and tests that ensure entropy_gpu is used before entropy_py/c would go here

# Tests for ofrak_gpu's correctness, eg tests for entropy_gpu's correctness, should NOT go here.
# The tests in this file should pass whether or not ofrak_gpu is installed in the test env, and
# should not rely on ofrak_gpu existing. Those tests should go in ofrak_gpu/ofrak_gpu_test.ofrak_gpu.ofrak_gpu_test
# """

import pytest
import os.path
import test_ofrak.components
from ofrak import OFRAKContext
from unittest.mock import MagicMock, Mock, patch
from typing import Any

from ofrak.core.entropy.entropy_py import entropy_py
from ofrak.core.entropy.entropy_c import entropy_c
from ofrak.core.entropy import DataSummaryAnalyzer, DataSummary

DEFAULT_WINDOW_SIZE = 256  # This should match what DataSummaryAnalyzer uses as its window size

TEST_FILES = [
    "hello.out",
    "arm_reloc_relocated.elf",
    "flash_test_magic.bin",
    "hello.rar",
    "imx7d-sdb.dtb",
    "simple_arm_gcc.o.elf",
]


def dummy_entropy_gpu(
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
def mock_ofrak_gpu_installed():
    mock_entropy_gpu = MagicMock(side_effect=dummy_entropy_gpu)
    mock_np = MagicMock()
    # Our mock frombuffer will return what it is given, which should be passed to dummy_entropy_gpu
    mock_np.frombuffer = Mock(side_effect=lambda x, dtype=None: x)

    with patch("ofrak.core.entropy.entropy.np", new=mock_np):
        with patch("ofrak.core.entropy.entropy.entropy_gpu", new=mock_entropy_gpu):
            with patch("ofrak.core.entropy.entropy.GPU_MODULE_INSTALLED", True):
                yield


@pytest.fixture
def mock_ofrak_gpu_missing():
    with patch("ofrak.core.entropy.entropy.GPU_MODULE_INSTALLED", False):
        yield


@pytest.mark.parametrize(
    "test_file_path",
    [os.path.join(test_ofrak.components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
@pytest.mark.usefixtures("mock_ofrak_gpu_installed")
async def test_analyzer_gpu(ofrak_context: OFRAKContext, test_file_path):
    """
    Ensures that, when the ofrak_gpu module is installed, the DataSummaryAnalyzer will use the
    ofrak_gpu.entropy_gpu.entropy_gpu() function for its entropy calculations, not the Python
    or C implementations.

    This is done using the patch_np_and_gpu fixture. Whether or not the ofrak_gpu module is
    installed alongside ofrak_core in the testing environment, this fixture will use patching to
    assess DataSummaryAnalyzer's behavior as if dummy_entropy_gpu was imported as entropy_gpu.
    Thus, by asserting that the computed entropy == dummy_entropy_gpu's result, we know the
    DataSummaryAnalyzer will use ofrak_gpu.entropy_gpu, if found, before core.entropy's C.
    """
    with open(test_file_path, "rb") as f:
        data = f.read()

    root = await ofrak_context.create_root_resource_from_file(test_file_path)
    await root.run(DataSummaryAnalyzer)
    data_summary = root.get_attributes(DataSummary)
    entropy = data_summary.entropy_samples

    # Asserts that DataSummaryAnalyzer uses entropy_gpu = dummy_entropy_gpu if it can be imported
    assert entropy == dummy_entropy_gpu(data, DEFAULT_WINDOW_SIZE, None)


@pytest.mark.parametrize(
    "test_file_path",
    [os.path.join(test_ofrak.components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
@pytest.mark.usefixtures("mock_ofrak_gpu_missing")
async def test_analyzer_standard(ofrak_context: OFRAKContext, test_file_path):
    """
    Only test on small files for two reasons:

    1. The sampling of large files may lead to spurious test failures.
    2. The reference method is *extremely* slow for even moderately sized files.

    Using the mock_ofrak_gpu_missing fixture, this case tests that, in the absence of ofrak_gpu,
    DataSummaryAnalyzer will fall back upon entropy_py/c. It also checks the correctness of
    entropy_py and entropy_c against each other.
    """

    with open(test_file_path, "rb") as f:
        data = f.read()

    c_implementation_entropy = entropy_c(data, 256, lambda s: None)
    py_implementation_entropy = entropy_py(data, 256)

    if len(data) < 256:
        assert c_implementation_entropy == b""
        assert py_implementation_entropy == b""

    assert _almost_equal(
        c_implementation_entropy, py_implementation_entropy
    ), f"Python and C entropy implementations for {test_file_path} differ."

    expected_entropy = c_implementation_entropy

    root = await ofrak_context.create_root_resource_from_file(test_file_path)
    # Due to mock_no_ofrak_gpu, we know this will fail to import entropy_gpu and will run entropy_c
    await root.run(DataSummaryAnalyzer)
    data_summary = root.get_attributes(DataSummary)
    entropy = data_summary.entropy_samples
    assert _almost_equal(
        entropy, expected_entropy
    ), f"Entropy analysis for {test_file_path} differs from reference entropy."


def _almost_equal(bytes1: bytes, bytes2: bytes) -> bool:
    """
    Return true if each pair of bytes in each position of two byte arrays differs by no more than
    one. For example: `[0, 1, 2]` and `[1, 2, 3]` are almost equal. `[2, 1, 2]` and `[0, 1,
    2]` are not.
    """
    if len(bytes1) != len(bytes2):
        return False

    for i in range(len(bytes1)):
        if abs(bytes1[i] - bytes2[i]) > 1:
            print(f"Inputs differ at byte {i} ({bytes1[i]} != {bytes2[i]})")
            return False
    return True
