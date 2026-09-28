"""
Test entropy analysis component functionality.

Requirements Mapping:
- REQ2.2
"""

import asyncio
import importlib.util
import os.path
import platform
import sys
import time

import pytest
from ofrak.core.entropy import (
    DataSummaryAnalyzer,
    MlxDataSummaryAnalyzer,
    MlxEntropyResource,
    TorchDataSummaryAnalyzer,
    TorchEntropyResource,
)
from ofrak.core.entropy.entropy_mlx import (
    MlxDataSummaryCache,
    _lookup_table,
    _sample_positions,
)
from ofrak.core.entropy.entropy_torch import (
    TorchDataSummaryCache,
    _lookup_table as _torch_lookup_table,
    _positions as _torch_positions,
    sample_entropy_torch,
)
from ofrak_type.error import NotFoundError

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


def test_mlx_sample_positions_are_exact():
    assert list(_sample_positions(512, 256, 2**20)) == list(range(256))
    assert list(_sample_positions(2048, 256, 4)) == [0, 448, 896, 1344]
    large_length = 2**34 + 512
    positions = _sample_positions(large_length, 256, 4)
    assert positions.itemsize == 8
    assert positions[-1] == 3 * (large_length - 256) // 4 > 2**32


def test_mlx_lookup_table():
    lookup = _lookup_table()
    assert len(lookup) == 257
    assert lookup[0] == lookup[1] == 0
    assert lookup[256] == 256 * 8 * 2**32


async def test_mlx_backend_selection(ofrak_context: OFRAKContext, monkeypatch):
    from ofrak.core.entropy import entropy_mlx

    expected = b"\x2a" * 4
    received = []

    def fake_entropy(data):
        received.append(data)
        return expected

    monkeypatch.setattr(entropy_mlx, "sample_entropy_mlx", fake_entropy)
    data = bytes(index % 256 for index in range(260))
    root = await ofrak_context.create_root_resource("entropy", data)
    compatibility_analyzer: DataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
        DataSummaryAnalyzer.get_id()
    )
    compatibility_before = await compatibility_analyzer.get_data_summary(root)
    analyzer: MlxDataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
        MlxDataSummaryAnalyzer.get_id()
    )
    summary = await analyzer.get_data_summary(root)
    compatibility_after = await compatibility_analyzer.get_data_summary(root)
    assert summary.entropy_samples == expected
    assert root.has_tag(MlxEntropyResource)
    assert root.get_attributes(MlxDataSummaryCache).cache_key == root.get_id().hex()
    assert compatibility_after == compatibility_before
    assert received == [data]


async def test_mlx_failure_cleans_up_tag(ofrak_context: OFRAKContext, monkeypatch):
    from ofrak.core.entropy import entropy_mlx

    def fake_fail(data):
        raise RuntimeError("simulated MLX failure")

    monkeypatch.setattr(entropy_mlx, "sample_entropy_mlx", fake_fail)
    root = await ofrak_context.create_root_resource(
        "entropy", bytes(index % 256 for index in range(260))
    )
    analyzer: MlxDataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
        MlxDataSummaryAnalyzer.get_id()
    )
    with pytest.raises(RuntimeError, match="simulated MLX failure"):
        await analyzer.get_data_summary(root)
    assert not root.has_tag(MlxEntropyResource)


async def test_mlx_analyzer_is_not_automatic(ofrak_context: OFRAKContext):
    root = await ofrak_context.create_root_resource("entropy", bytes(range(255)))
    await root.auto_run(all_analyzers=True)
    with pytest.raises(NotFoundError):
        root.get_attributes(MlxDataSummaryCache)


def test_mlx_backend_dependency_error(monkeypatch):
    import builtins

    from ofrak.core.entropy.entropy_mlx import sample_entropy_mlx

    original_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "mlx.core":
            raise ImportError("blocked for test")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    with pytest.raises(ModuleNotFoundError, match="ofrak\\[entropy-mlx\\]"):
        sample_entropy_mlx(bytes(range(256)) + b"\x00")


@pytest.mark.skipif(
    sys.platform != "darwin"
    or platform.machine() != "arm64"
    or importlib.util.find_spec("mlx") is None,
    reason="MLX Metal requires Apple Silicon",
)
def test_mlx_backend_matches_python_entropy():
    from ofrak.core.entropy.entropy_mlx import sample_entropy_mlx

    fixtures = [
        bytes([0]) * 512,
        bytes(range(256)) * 2,
        bytes((index * 73 + index // 11) % 256 for index in range(4096)),
    ]
    for data in fixtures:
        assert sample_entropy_mlx(data) == entropy_py(data, 256)

    sampled = fixtures[-1]
    full = entropy_py(sampled, 256)
    positions = _sample_positions(len(sampled), 256, 64)
    expected = bytes(full[position] for position in positions)
    assert sample_entropy_mlx(sampled, max_samples=64) == expected


def test_torch_sample_positions_are_exact():
    pytest.importorskip("torch")
    assert list(_torch_positions(512, 256, 2**20).numpy()) == list(range(256))
    assert list(_torch_positions(2048, 256, 4).numpy()) == [0, 448, 896, 1344]
    large_length = 2**34 + 512
    positions = _torch_positions(large_length, 256, 4)
    assert positions.element_size() == 8
    assert int(positions[-1]) == 3 * (large_length - 256) // 4 > 2**32


def test_torch_lookup_table():
    lookup = _torch_lookup_table()
    assert len(lookup) == 257
    assert lookup[0] == lookup[1] == 0
    assert lookup[256] == 256 * 8 * 2**32


async def test_torch_backend_selection(ofrak_context: OFRAKContext, monkeypatch):
    from ofrak.core.entropy import entropy_torch

    expected = b"\x2a" * 4
    received = []

    def fake_entropy(data):
        received.append(data)
        return expected

    monkeypatch.setattr(entropy_torch, "sample_entropy_torch", fake_entropy)
    data = bytes(index % 256 for index in range(260))
    root = await ofrak_context.create_root_resource("entropy", data)
    compatibility_analyzer: DataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
        DataSummaryAnalyzer.get_id()
    )
    compatibility_before = await compatibility_analyzer.get_data_summary(root)
    analyzer: TorchDataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
        TorchDataSummaryAnalyzer.get_id()
    )
    summary = await analyzer.get_data_summary(root)
    compatibility_after = await compatibility_analyzer.get_data_summary(root)
    assert summary.entropy_samples == expected
    assert root.has_tag(TorchEntropyResource)
    assert root.get_attributes(TorchDataSummaryCache).cache_key == root.get_id().hex()
    assert compatibility_after == compatibility_before
    assert received == [data]


async def test_torch_failure_cleans_up_tag(ofrak_context: OFRAKContext, monkeypatch):
    from ofrak.core.entropy import entropy_torch

    def fake_fail(data):
        raise RuntimeError("simulated Torch failure")

    monkeypatch.setattr(entropy_torch, "sample_entropy_torch", fake_fail)
    root = await ofrak_context.create_root_resource(
        "entropy", bytes(index % 256 for index in range(260))
    )
    analyzer: TorchDataSummaryAnalyzer = ofrak_context.component_locator.get_by_id(
        TorchDataSummaryAnalyzer.get_id()
    )
    with pytest.raises(RuntimeError, match="simulated Torch failure"):
        await analyzer.get_data_summary(root)
    assert not root.has_tag(TorchEntropyResource)


async def test_torch_analyzer_is_not_automatic(ofrak_context: OFRAKContext):
    root = await ofrak_context.create_root_resource("entropy", bytes(range(255)))
    await root.auto_run(all_analyzers=True)
    with pytest.raises(NotFoundError):
        root.get_attributes(TorchDataSummaryCache)


def test_torch_backend_dependency_error(monkeypatch):
    import builtins

    from ofrak.core.entropy.entropy_torch import sample_entropy_torch

    original_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "torch":
            raise ImportError("blocked for test")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    with pytest.raises(ModuleNotFoundError, match="ofrak\\[entropy-torch\\]"):
        sample_entropy_torch(bytes(range(256)) + b"\x00")


def test_torch_backend_matches_python_entropy():
    pytest.importorskip("torch")
    from ofrak.core.entropy.entropy_torch import sample_entropy_torch

    fixtures = [
        bytes([0]) * 512,
        bytes(range(256)) * 2,
        bytes((index * 73 + index // 11) % 256 for index in range(4096)),
    ]
    for data in fixtures:
        assert sample_entropy_torch(data, device="cpu") == entropy_py(data, 256)

    sampled = fixtures[-1]
    full = entropy_py(sampled, 256)
    positions = _torch_positions(len(sampled), 256, 64)
    expected = bytes(full[int(position)] for position in positions)
    assert sample_entropy_torch(sampled, max_samples=64, device="cpu") == expected


def test_torch_backend_matches_ofrak_c():
    pytest.importorskip("torch")
    from ofrak.core.entropy.entropy_torch import sample_entropy_torch

    data = bytes((index * 73 + index // 11) % 256 for index in range(8192))
    assert sample_entropy_torch(data, device="cpu") == entropy_c(data, 256)
