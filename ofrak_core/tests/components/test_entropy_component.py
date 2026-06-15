"""
Test entropy analysis component functionality.

Requirements Mapping:
- REQ2.2
"""
import asyncio
import os.path
import time

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
    Test that the entropy analyzer produces consistent results between Python and C implementations.

    This test verifies that:
    - The C and Python entropy implementations produce nearly identical results for test files
    - The entropy analysis component correctly computes entropy samples for resources

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


@pytest.mark.skipif(
    not os.path.isdir(f"/proc/{os.getpid()}/fd"),
    reason="Requires /proc/<pid>/fd (Linux only)",
)
async def test_entropy_does_not_leak_fds(ofrak_context: OFRAKContext):
    """
    Regression test for the ProcessPoolExecutor FD leak in DataSummaryAnalyzer.
    """
    fd_dir = f"/proc/{os.getpid()}/fd"
    asset_path = os.path.join(components.ASSETS_DIR, "hello.out")
    before = len(os.listdir(fd_dir))

    iterations = 5
    for _ in range(iterations):
        root_resource = await ofrak_context.create_root_resource_from_file(asset_path)
        await root_resource.run(DataSummaryAnalyzer)
    after = len(os.listdir(fd_dir))

    delta = after - before
    assert delta < 10, (
        f"DataSummaryAnalyzer leaked {delta} FDs across {iterations} iterations "
        f"({before} -> {after})."
    )


async def test_entropy_parallel_faster_than_sequential(ofrak_context: OFRAKContext):
    """
    Time four entropy analyses run sequentially vs. run concurrently with
    `asyncio.gather`, and assert that the concurrent version is faster.
    """
    asset_path = os.path.join(components.ASSETS_DIR, "uimage_multi")

    async def analyze_once():
        root_resource = await ofrak_context.create_root_resource_from_file(asset_path)
        analyzer: DataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
            DataSummaryAnalyzer.get_id()
        )
        return await analyzer.get_data_summary(root_resource)

    # Sequential:
    start = time.perf_counter()
    await analyze_once()
    await analyze_once()
    await analyze_once()
    await analyze_once()
    sequential_time = time.perf_counter() - start

    # Parallel:
    start = time.perf_counter()
    await asyncio.gather(analyze_once(), analyze_once(), analyze_once(), analyze_once())
    parallel_time = time.perf_counter() - start

    assert parallel_time < sequential_time * 0.85, (
        f"Expected parallel analysis to be at least 15% faster, but sequential took "
        f"{sequential_time:.3f}s and parallel took {parallel_time:.3f}s "
        f"({parallel_time / sequential_time:.0%} of sequential)."
    )
