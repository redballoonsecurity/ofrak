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


@pytest.fixture
def elf_test_directory(tmpdir):
    makefile_path = os.path.join(tmpdir, "Makefile")
    c_source_path = os.path.join(tmpdir, "program.c")

    with open(makefile_path, "w") as f:
        f.write(MAKEFILE_CONTENTS)
    with open(c_source_path, "w") as f:
        f.write(C_SOURCE_CONTENTS)

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
