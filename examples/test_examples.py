"""
This module tests the various example scripts in the examples directory to ensure they
function correctly and produce expected outputs.
"""
import os
import subprocess

import pytest

try:
    import xattr
except ImportError:
    import ofrak_core.ofrak.core.xattr_stub as xattr  # type: ignore[no-redef]

from examples.ex5_binary_extension import SEVEN_KITTEH
from examples.ex8_recursive_unpacking import KITTEH as KITTEH_ASCII
from hashlib import md5

EXAMPLE_DIRECTORY = os.path.dirname(__file__)


@pytest.fixture(scope="session")
def move_to_test_directory():
    current_directory = os.getcwd()
    os.chdir(EXAMPLE_DIRECTORY)
    yield
    os.chdir(current_directory)


@pytest.fixture(autouse=True, scope="session")
def make_program(move_to_test_directory):
    command = ["make", "-C", "src"]
    subprocess.run(command, check=True)


@pytest.fixture(autouse=True, scope="session")
def make_program_kitteh(move_to_test_directory):
    command = ["make", "-C", "src/example_6"]
    subprocess.run(command, check=True)


def test_example_1(tmp_path):
    """
    Test that the executable built by ex1_simple_string_modification.py prints "Meow!" to stdout.

    This test verifies that:
    - The example script creates an executable file
    - The executable produces expected stdout output
    """
    file = tmp_path / "example_1.out"
    command = ["python3", "ex1_simple_string_modification.py", "--output-file-name", str(file)]
    subprocess.run(command, check=True)
    os.chmod(str(file), 0o755)
    stdout = subprocess.run(str(file), capture_output=True).stdout
    assert stdout == b"Meow!\n"


def test_example_2(tmp_path):
    """
    Test that the executable built by ex2_simple_code_modification.py prints "Hello, World!" in an
    infinite loop.

    This test verifies that:
    - The example script creates an executable file
    - The executable runs for a short time and produces repeated output
    """
    file = tmp_path / "example_2.out"
    command = ["python3", "ex2_simple_code_modification.py", "--output-file-name", str(file)]
    subprocess.run(command, check=True)
    os.chmod(str(file), 0o755)
    with pytest.raises(subprocess.TimeoutExpired) as exc_info:
        subprocess.run(str(file), capture_output=True, timeout=0.1)
        assert (
            b"Hello, World!\nHello, World!\nHello, World!\nHello, World!" in exc_info.value.stdout
        )


def test_example_3(tmp_path):
    """
    Test that the executable built by ex3_binary_format_modification.py results in a Segmentation
    fault.

    This test verifies that:
    - The example script creates an executable file
    - The executable crashes with a segmentation fault
    """
    file = tmp_path / "example_3.out"
    command = ["python3", "ex3_binary_format_modification.py", "--output-file-name", str(file)]
    subprocess.run(command, check=True)
    os.chmod(str(file), 0o775)
    with pytest.raises(subprocess.CalledProcessError, match="Signals.SIGSEGV"):
        subprocess.check_call(str(file))


def test_example_4(tmp_path):
    """
    Test that the executable built by ex4_filesystem_modification.py changes
     * string
     * permissions
     * xattrs

    This test verifies that:
    - The example script creates a squashfs filesystem that can be unpacked
    - The unpacked files have correct permissions
    - The unpacked files have correct extended attributes
    - The unpacked executable produces expected output
    """
    file = tmp_path / "example_4.out"
    command = ["python3", "ex4_filesystem_modification.py", "--output-file-name", str(file)]
    subprocess.run(command, check=True)
    unsquashfs = ["unsquashfs", "-d", tmp_path / "squashfs-root", str(file)]
    subprocess.run(unsquashfs, check=True)
    target_file = tmp_path / "squashfs-root" / "src" / "program"
    stat = os.lstat(target_file)
    assert stat.st_mode == 0o100755
    assert xattr.getxattr(target_file, "user.foo") == b"bar"
    os.chmod(str(target_file), 0o755)
    stdout = subprocess.run(str(target_file), capture_output=True).stdout
    assert stdout == b"More meow!\n"


def test_example_5(tmp_path):
    """
    Test the the executable built by ex5_binary_extension.py prints seven kitteh.

    This test verifies that:
    - The example script creates an executable file
    - The executable produces expected stdout output
    """
    file = tmp_path / "example_5.out"
    command = ["python3", "ex5_binary_extension.py", "--output-file-name", str(file)]
    subprocess.run(command, check=True)
    os.chmod(str(file), 0o755)
    stdout = subprocess.run(str(file), capture_output=True).stdout
    assert stdout[:-1] == SEVEN_KITTEH[:-1]


def test_example_6(tmp_path):
    """
    Test that the executable built by ex6_code_modification_without_extension.py prints kitteh and
    not Hello, World!

    This test verifies that:
    - The example script creates an executable file
    - The executable produces expected stdout output
    """
    file = tmp_path / "example_6.out"
    command = [
        "python3",
        "ex6_code_modification_without_extension.py",
        "--output-file-name",
        str(file),
    ]
    subprocess.run(command, check=True)
    os.chmod(str(file), 0o755)
    stdout = subprocess.run(str(file), capture_output=True).stdout
    assert stdout == b"kitteh! demands obedience...\n"


def test_example_7(tmp_path):
    """
    Test that the executable built by ex7_code_insertion_with_extension.py prints capital
    "HELLO, WORLD!".

    This test verifies that:
    - The example script creates an executable file
    - The executable produces expected stdout output
    """
    file = tmp_path / "example_7.out"
    command = ["python3", "ex7_code_insertion_with_extension.py", "--output-file-name", str(file)]
    subprocess.run(command, check=True)
    os.chmod(str(file), 0o755)
    stdout = subprocess.run(str(file), capture_output=True).stdout
    assert stdout == b"HELLO, WORLD!\n"


def test_example_8(tmp_path):
    """
    Test that the archive built by ex8_recursive_unpacking.py contains the expected file, and that
    the file contains the expected contents

    This test verifies that:
    - The example script creates a tar.gz archive
    - The archive can be successfully unpacked
    - The inner archive is correctly extracted
    - The inner file has correct content
    """
    file = tmp_path / "example_8.tar.gz"
    command = ["python3", "ex8_recursive_unpacking.py", "--output-file-name", str(file)]
    subprocess.run(command, check=True)

    os.chdir(str(tmp_path))

    untar_outer = ["tar", "-xzf", "example_8.tar.gz"]
    stderr = subprocess.run(untar_outer, check=True, capture_output=True).stderr
    assert os.path.isfile("example_8_inner.tar.gz"), f"Unzipping failed: \n{stderr.decode()}"

    untar = ["tar", "-xzf", "example_8_inner.tar.gz"]
    stderr = subprocess.run(untar, check=True, capture_output=True).stderr
    assert os.path.isfile("meow.txt"), f"Untarring failed: \n{stderr.decode()}"
    with open("meow.txt") as f:
        data = f.read().strip()
        assert data == KITTEH_ASCII.strip(), f"Inner file meow.txt had incorrect contents {data}"
    os.chdir(EXAMPLE_DIRECTORY)


def test_example_9(tmp_path):
    """
    Test that the modified flash dump contains the inserted string and matches the right md5sum

    This test verifies that:
    - The example script creates a modified flash dump
    - The flash dump contains the expected inserted string
    - The flash dump has the expected md5 checksum
    """
    file = tmp_path / "repacked_flash_dump.bin"
    command = ["python3", "ex9_flash_modification.py", "--output-file", str(file)]
    subprocess.run(command, check=True)

    with open(str(file), "rb") as f:
        data = f.read()
        expected_string = b"INSERT ME!"
        assert expected_string in data, f"{str(file)} doesn't contain the {expected_string} string"
        md5sum = md5(data).hexdigest()
        expected_md5 = "6277eb7c64b12f247913eb4e875f5758"
        assert (
            md5sum == expected_md5
        ), f"md5sum for '{str(file)}' {md5sum} (expected {expected_md5})"
