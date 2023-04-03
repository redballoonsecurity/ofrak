import os
import subprocess

import pytest

MAKEFILE_CONTENTS = """
CC=gcc

default: program

program.o: program.c $(HEADERS)
	$(CC) -c program.c -fno-asynchronous-unwind-tables -o program.o

program: program.o
	$(CC) program.o -o program

program_no_reloc: program.o
	$(CC) program.o -no-pie -o program_no_reloc

program_relocated: program_relocated.o
	$(CC) program_relocated.o -o program_relocated

large_elf.o: large_elf.c $(HEADERS)
	$(CC) -c large_elf.c -o large_elf.o

large_elf: large_elf.o
	$(CC) large_elf.o -no-pie -o large_elf 
"""

C_SOURCE_CONTENTS = """
#include <stdio.h>

int foo();
int bar();

int main() {
   printf("Hello, World!\\n");
   return foo();
}

int foo() {
    return 12;
}

int bar() {
    return 24;
}


"""

LARGE_SOURCE_CONTENTS_HEADER = """
int foo();
int bar();

int main() {
   return bar();
}

"""

LARGE_SOURCE_CONTENTS_FOOTER = """

int foo() {
    return 12;
}

int bar() {
    return 24;
}


"""

PATCH_CONTENTS = """
int noop0();

int baz()
{
    noop0();
    return 36;
}
"""


def create_noops():
    noops = []

    i = 0

    for i in range(8000):
        instruction = f"int noop{i}(){{}}"
        noops.append(instruction)

    return noops


@pytest.fixture
def elf_test_directory(tmpdir):
    makefile_path = os.path.join(tmpdir, "Makefile")
    c_source_path = os.path.join(tmpdir, "program.c")
    large_source_path = os.path.join(tmpdir, "large_elf.c")

    patch_dir = os.path.join(tmpdir, "source_dir")
    if not os.path.exists(patch_dir):
        os.mkdir(patch_dir)
    patch_path = os.path.join(patch_dir, "patch.c")

    noops = create_noops()

    LARGE_SOURCE_CONTENTS = LARGE_SOURCE_CONTENTS_HEADER
    for noop in noops:
        LARGE_SOURCE_CONTENTS += noop
    LARGE_SOURCE_CONTENTS += LARGE_SOURCE_CONTENTS_FOOTER

    with open(makefile_path, "w") as f:
        f.write(MAKEFILE_CONTENTS)
    with open(c_source_path, "w") as f:
        f.write(C_SOURCE_CONTENTS)
    with open(large_source_path, "w") as f:
        f.write(LARGE_SOURCE_CONTENTS)
    with open(patch_path, "w") as f:
        f.write(PATCH_CONTENTS)

    return tmpdir


@pytest.fixture
def elf_object_file(elf_test_directory):
    subprocess.run(["make", "-C", elf_test_directory, "program.o"])
    return os.path.join(elf_test_directory, "program.o")


@pytest.fixture
def elf_executable_file(elf_test_directory):
    subprocess.run(["make", "-C", elf_test_directory, "program"])
    return os.path.join(elf_test_directory, "program")


@pytest.fixture
def elf_no_pie_executable_file(elf_test_directory):
    subprocess.run(["make", "-C", elf_test_directory, "program_no_reloc"])
    return os.path.join(elf_test_directory, "program_no_reloc")


@pytest.fixture
def large_elf_source_file(elf_test_directory):
    return os.path.join(elf_test_directory, "large_elf.c")


@pytest.fixture
def large_elf_object_file(elf_test_directory):
    subprocess.run(["make", "-C", elf_test_directory, "large_elf.o"])
    return os.path.join(elf_test_directory, "large_elf.o")


@pytest.fixture
def large_elf_file(elf_test_directory):
    subprocess.run(["make", "-C", elf_test_directory, "large_elf"])
    return os.path.join(elf_test_directory, "large_elf")


@pytest.fixture
def patch_file(elf_test_directory):
    return os.path.join(elf_test_directory, "source_dir", "patch.c")
