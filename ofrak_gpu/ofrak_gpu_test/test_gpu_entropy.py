import os
import pytest
import numpy as np

from ofrak_gpu.entropy_gpu import entropy_gpu, pick_pyopencl_device

from ofrak_gpu_test import ASSETS_DIR
from test_ofrak.components import ASSETS_DIR as CORE_ASSETS_DIR

# The reference implementations to test against
try:
    pass
except:
    pass


def test_platform_picking():
    """
    A basic check that pick_pyopencl_device will choose the device with more max_compute_units
    """
    chosen_platform, chosen_device = pick_pyopencl_device()

    # Since we know at least oclgrind and pocl will be installed for the test, and pocl has more
    # compute units than oclgrind, we should not pick oclgrind. As of now, we don't check that pocl
    # was picked, since there could be a different, more powerful platform on the test environment
    assert chosen_device != "Oclgrind Simulator"
    assert chosen_platform != "Oclgrind"


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


# These test files should be in trest_ofrak.components.ASSETS_DIR
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
    [os.path.join(CORE_ASSETS_DIR, filename) for filename in TEST_FILES],
)
def test_against_entropy_func():
    """
    Tests entropy_gpu's results against entropy_func (c/py) from ofrak core
    """
    # TODO
