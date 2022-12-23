import os.path

import pytest
from ofrak.core.entropy import DataSummaryAnalyzer, DataSummary

from ofrak import OFRAKContext
import test_ofrak.components
from ofrak.core.entropy.reference_entropy import entropy_func

TEST_FILES = [
    "hello.out",
    "arm_reloc_relocated.elf",
    "hello.rar",
    "imx7d-sdb.dtb",
    "simple_arm_gcc.o.elf",
]


@pytest.mark.parametrize(
    "test_file_path",
    [os.path.join(test_ofrak.components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
async def test_analyzer(ofrak_context: OFRAKContext, test_file_path):
    """
    Only test on small files for two reasons:

    1. The sampling of large files may lead to spurious test failures.
    2. The reference method is *extremely* slow for even moderately sized files.
    """
    root = await ofrak_context.create_root_resource_from_file(test_file_path)
    await root.run(DataSummaryAnalyzer)
    data_summary = root.get_attributes(DataSummary)
    entropy = data_summary.entropy_samples
    data = await root.get_data()
    assert len(entropy) == len(entropy_func(data, len(data), 256, lambda s: None))
    assert _almost_equal(
        entropy, entropy_func(data, len(data), 256, lambda s: None)
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
