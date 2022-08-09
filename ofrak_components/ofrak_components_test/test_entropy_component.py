import math
import os.path
from typing import List

import pytest
from ofrak_components.entropy import DataSummaryAnalyzer, DataSummary

from ofrak import OFRAKContext
import test_ofrak.components


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
    assert _almost_equal(
        entropy, _reference_entropy(await root.get_data())
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


def _reference_entropy(data: bytes, window_size: int = 256) -> bytes:
    """
    Return a list of entropy values where each value represents the Shannon entropy of the byte
    value distribution over a fixed-size, sliding window.
    """

    # Create a histogram, and populate it with initial values
    histogram = [0] * 256
    for b in data[:window_size]:
        histogram[b] += 1

    # Calculate the entropy using a sliding window
    entropy = [0] * (len(data) - window_size)
    for i in range(len(entropy)):
        entropy[i] = math.floor(255 * _shannon_entropy(histogram, window_size))
        histogram[data[i]] -= 1
        histogram[data[i + window_size]] += 1
    return bytes(entropy)


def _shannon_entropy(distribution: List[int], window_size: int) -> float:
    """
    Return the Shannon entropy of the input probability distribution (represented as a histogram
    counting byte occurrences over a window of known size).

    Shannon entropy represents how uniform a probability distribution is. Since more uniform
    implies less predictable (because the probability of any outcome is equally likely in a
    uniform distribution), a sample with higher entropy is "more random" than one with lower
    entropy. More here: <https://en.wikipedia.org/wiki/Entropy_(information_theory)>.
    """

    result = 0
    for num_occurrences in distribution:
        probability = num_occurrences / window_size
        # Note that the zero check is required because the domain of log2 is the positive reals
        result += probability * math.log2(probability) if probability != 0.0 else 0.0
    return -result / math.log2(window_size)
