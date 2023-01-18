import os


def hello_elf() -> bytes:
    """
    A hello world ELF file for testing.

    Used as a pytest fixture in the:
        - ofrak_ghidra_test
        - ofrak_binary_ninja_test
        - test_ofrak_server
    """
    assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "./assets"))
    asset_path = os.path.join(assets_dir, "hello.out")
    with open(asset_path, "rb") as f:
        return f.read()
