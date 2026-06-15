import os

import pytest


@pytest.fixture(scope="session")
def elf_test_directory():
    return os.path.join(os.path.dirname(__file__), "assets")


@pytest.fixture(scope="session")
def elf_object_file(elf_test_directory):
    return os.path.join(elf_test_directory, "program.o")


@pytest.fixture(scope="session")
def elf_executable_file(elf_test_directory):
    return os.path.join(elf_test_directory, "program")


@pytest.fixture(scope="session")
def elf_permstest_executable_file(elf_test_directory):
    return os.path.join(elf_test_directory, "permstest_elf")


@pytest.fixture(scope="session")
def elf_no_pie_executable_file(elf_test_directory):
    return os.path.join(elf_test_directory, "program_no_reloc")


@pytest.fixture(scope="session")
def large_elf_source_file(elf_test_directory):
    return os.path.join(elf_test_directory, "large_elf.c")


@pytest.fixture(scope="session")
def large_elf_object_file(elf_test_directory):
    return os.path.join(elf_test_directory, "large_elf.o")


@pytest.fixture(scope="session")
def large_elf_file(elf_test_directory):
    return os.path.join(elf_test_directory, "large_elf")


@pytest.fixture(scope="session")
def patch_file(elf_test_directory):
    return os.path.join(elf_test_directory, "source_dir", "patch.c")


@pytest.fixture(scope="session")
def hello_elf(elf_test_directory) -> bytes:
    """
    A hello world ELF file for testing.

    Used as a pytest fixture in the:
        - ofrak_ghidra tests
        - ofrak_binary_ninja tests
        - test_ofrak_server
    """
    asset_path = os.path.join(elf_test_directory, "hello.out")
    with open(asset_path, "rb") as f:
        return f.read()
