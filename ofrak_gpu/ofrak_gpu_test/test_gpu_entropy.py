import os
import pytest
import numpy as np

from ofrak_gpu.entropy_gpu import entropy_gpu

from ofrak_gpu_test import ASSETS_DIR
from test_ofrak.components import ASSETS_DIR as CORE_ASSETS_DIR

# The reference implementations to test against
try:
    from ofrak.core.entropy.entropy_c import entropy_c as reference_entropy
except:
    from ofrak.core.entropy.entropy_py import entropy_py as reference_entropy


def test_edge_entropies():
    """
    Test entropy_gpu against files that with known edge-case Shannon entropy values (eg 0, 255)
    """
    with open(os.path.join(ASSETS_DIR, "zero_entropy_10_B_windows.bin"), "rb") as f:
        data: np.ndarray = np.frombuffer(f.read(), dtype=np.uint8)

    # This should have 256 10-byte windows of 0 entropy
    assert entropy_gpu(data, window_size=10) == bytes([0] * 256)
    # This should have 512 5-byte windows of 0 entropy
    assert entropy_gpu(data, window_size=5) == bytes([0] * 512)
    # Since window_size > len(data), should not compute anything
    assert entropy_gpu(data, window_size=len(data) + 1) == b""

    with open(os.path.join(ASSETS_DIR, "max_entropy_256_B_windows.bin"), "rb") as f:
        data: np.ndarray = np.frombuffer(f.read(), dtype=np.uint8)

    # This should have 2 256-byte windows of 255 entropy
    assert entropy_gpu(data, window_size=256) == b"\xff\xff"


# These test files should be in test_ofrak.components.ASSETS_DIR
CORE_TEST_FILES = [
    "hello.out",
    "arm_reloc_relocated.elf",
    "flash_test_magic.bin",
    "hello.rar",
    "imx7d-sdb.dtb",
    "simple_arm_gcc.o.elf",
]

# These test files should be in ofrak_gpu_test.ASSETS_DIR
GPU_TEST_FILES = ["max_entropy_256_B_windows.bin"]

WINDOW_SIZE = 256


@pytest.mark.parametrize(
    "test_file_path",
    [os.path.join(CORE_ASSETS_DIR, filename) for filename in CORE_TEST_FILES]
    + [os.path.join(ASSETS_DIR, filename) for filename in GPU_TEST_FILES],
)
def test_against_entropy_func(test_file_path):
    """
    Tests entropy_gpu's results against entropy_func (c/py) from ofrak core
    """
    with open(test_file_path, "rb") as f:
        data: np.ndarray = np.frombuffer(f.read(), dtype=np.uint8)

    gpu_results = entropy_gpu(data, WINDOW_SIZE)
    core_results = reference_entropy(data.tobytes(), WINDOW_SIZE)

    if len(data) < WINDOW_SIZE:
        assert gpu_results == b"" and gpu_results == core_results
        return

    # Since these algorithms use the sliding windows differently, with entropy_gpy soliding
    # WINDOW_SIZE bytes at a time and the reference entropy functions sliding 1 byte at a
    # time, core_results has far more results, and we only compare one every WINDOW_SIZE

    for i in range(len(gpu_results)):
        # Ensure that they differ by no more than a difference in rounding
        if i * WINDOW_SIZE == len(core_results):
            assert abs(gpu_results[i] - core_results[WINDOW_SIZE * i - 1]) <= 1
        else:
            assert abs(gpu_results[i] - core_results[WINDOW_SIZE * i]) <= 1
