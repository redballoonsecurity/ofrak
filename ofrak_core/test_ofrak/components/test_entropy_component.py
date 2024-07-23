"""
Tests for the DataSummaryAnalyzer that expect ofrak_gpu to NOT be installed go here. See fixtures.

For example, tests for the correctness of entropy_py/c, tests that ensure they are used in the
absence of ofrak_gpu, and tests that ensure entropy_c is used before entropy_py would go here.

Tests that use ofrak_gpu, eg to test that entropy_gpu is used before entropy_py/c, don't go here;
see test_entropy_component_gpu.py and its fixtures.
"""
import sys
import pytest
import os.path
from unittest.mock import patch
from ofrak import OFRAKContext
import test_ofrak.components
from ofrak.core.entropy.entropy_py import entropy_py
from ofrak.core.entropy.entropy_c import entropy_c


TEST_FILES = [
    "hello.out",
    "arm_reloc_relocated.elf",
    "flash_test_magic.bin",
    "hello.rar",
    "imx7d-sdb.dtb",
    "simple_arm_gcc.o.elf",
]


@pytest.fixture
def mock_no_ofrak_gpu():
    with patch.dict(sys.modules, {"ofrak_gpu": None}):
        yield


@pytest.mark.parametrize(
    "test_file_path",
    [os.path.join(test_ofrak.components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
async def test_analyzer_standard(ofrak_context: OFRAKContext, test_file_path, mock_no_ofrak_gpu):
    from ofrak.core.entropy.entropy import DataSummary, DataSummaryAnalyzer

    """
    Only test on small files for two reasons:

    1. The sampling of large files may lead to spurious test failures.
    2. The reference method is *extremely* slow for even moderately sized files.

    Using the mock_no_ofrak_gpu fixture, this case tests that, in the absence of ofrak_gpu,
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
