"""
Tests for the DataSummaryAnalyzer that expect ofrak_gpu to NOT be installed go here. See fixtures.

For example, tests for the correctness of entropy_py/c, tests that ensure they are used in the
absence of ofrak_gpu, and tests that ensure entropy_c is used before entropy_py would go here.

Tests that use ofrak_gpu, eg to test that entropy_gpu is used before entropy_py/c, don't go here;
see test_entropy_component_gpu.py and its fixtures.
"""
import builtins
import sys
import importlib
import os.path
import pytest

from ofrak import OFRAKContext
import test_ofrak.components
from ofrak.core.entropy.entropy_py import entropy_py
from ofrak.core.entropy.entropy_c import entropy_c


@pytest.fixture(autouse=True)
def reload_entropy():
    """
    A fixture, automatically used before each test case, that triggers a module reload for entropy.
    This process is required for test that don't use mock_no_ofrak_gpu to import entropy correctly.
    """
    import ofrak.core.entropy as entropy_module

    importlib.reload(entropy_module)


@pytest.fixture
def mock_no_ofrak_gpu(monkeypatch):
    """
    A fixture used to make imports from ofrak_gpu act as if ofrak_gpu has not been installed,
    whether or not ofrak_gpu is installed on the test environment. Cleanup ensures that other
    test cases are unaffected, and can import from ofrak_gpu normally if needed.
    """
    import ofrak.core.entropy as entropy_module
    import ofrak.core.entropy.entropy as entropy_entropy_module

    real_import = builtins.__import__

    def monkey_import_notfound(name, globals=None, locals=None, fromlist=(), level=0):
        """
        Imports everything as normal, except imports from the ofrak_gpu module, which will fail.
        Used to mock ofrak_gpu not being installed, even if it is.
        """
        if name.startswith("ofrak_gpu."):
            raise ModuleNotFoundError(f"Mock module not found for {name}")

        return real_import(name, globals=globals, locals=locals, fromlist=fromlist, level=level)

    # Replace builtin import function with custom importer and reload modules
    monkeypatch.delitem(sys.modules, "ofrak_gpu", raising=False)
    monkeypatch.setattr(builtins, "__import__", monkey_import_notfound)

    importlib.reload(entropy_entropy_module)
    importlib.reload(entropy_module)

    yield

    monkeypatch.undo()

    importlib.reload(entropy_module)
    importlib.reload(entropy_entropy_module)


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
    [os.path.join(test_ofrak.components.ASSETS_DIR, filename) for filename in TEST_FILES],
)
@pytest.mark.usefixtures("mock_no_ofrak_gpu")
async def test_analyzer_standard(ofrak_context: OFRAKContext, test_file_path):
    """
    Only test on small files for two reasons:

    1. The sampling of large files may lead to spurious test failures.
    2. The reference method is *extremely* slow for even moderately sized files.

    Using the mock_no_ofrak_gpu fixture, this case tests that, in the absence of ofrak_gpu,
    DataSummaryAnalyzer will fall back upon entropy_py/c. It also checks the correctness of
    entropy_py and entropy_c against each other.
    """
    # These imports must be done inside the test function, as they must be run *after* the fixture
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
