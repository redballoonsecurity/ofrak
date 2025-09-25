import os.path

import pytest
from ofrak.core.entropy import DataSummaryAnalyzer

from ofrak import OFRAKContext
from .. import components
from ofrak.core.entropy.entropy_py import entropy_py
from ofrak.core.entropy.entropy_c import get_entropy_c

entropy_c = get_entropy_c()

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
    [os.path.join(components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
async def test_analyzer(ofrak_context: OFRAKContext, test_file_path):
    """
    Only test on small files for two reasons:

    1. The sampling of large files may lead to spurious test failures.
    2. The reference method is *extremely* slow for even moderately sized files.
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
    data_summary_analyzer: DataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
        DataSummaryAnalyzer.get_id()
    )
    data_summary = await data_summary_analyzer.get_data_summary(root)
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
