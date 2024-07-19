import builtins
import sys
import importlib
import os.path
import logging
import datetime
import pytest
import ofrak.core.entropy.entropy as entropy_module

from ofrak import OFRAKContext
import test_ofrak.components
from ofrak.core.entropy.entropy_py import entropy_py
from ofrak.core.entropy.entropy_c import entropy_c

TEST_FILES = [
    "hello.out",
    # "arm_reloc_relocated.elf",
    # "flash_test_magic.bin",
    # "hello.rar",
    # "imx7d-sdb.dtb",
    # "simple_arm_gcc.o.elf",
]


@pytest.fixture
def ofrak_gpu_not_installed(monkeypatch):
    real_import = builtins.__import__

    def monkey_import_notfound(name, globals=None, locals=None, fromlist=(), level=0):
        """
        Imports everything as normal, except imports from the ofrak_gpu module, which will fail.
        """
        if name.startswith("ofrak_gpu."):
            print(
                f"Throwing error for name={name} at {datetime.datetime.now().strftime('%H:%M:%S:%f')}"
            )
            raise ModuleNotFoundError(f"Mocked module not found {name}")

        return real_import(name, globals=globals, locals=locals, fromlist=fromlist, level=level)

    # Replace builtin import function with custom importer and reload modules
    monkeypatch.delitem(sys.modules, "ofrak_gpu", raising=False)
    monkeypatch.setattr(builtins, "__import__", monkey_import_notfound)
    importlib.reload(entropy_module)


@pytest.mark.parametrize(
    "test_file_path",
    [os.path.join(test_ofrak.components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
@pytest.mark.usefixtures("ofrak_gpu_not_installed")
async def test_analyzer_standard(ofrak_context: OFRAKContext, test_file_path):
    """
    Only test on small files for two reasons:

    1. The sampling of large files may lead to spurious test failures.
    2. The reference method is *extremely* slow for even moderately sized files.
    """
    logging.error(
        f"Running test case with import failure at {datetime.datetime.now().strftime('%H:%M:%S:%f')}"
    )
    importlib.reload(entropy_module)
    from ofrak.core.entropy import DataSummary, DataSummaryAnalyzer

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
