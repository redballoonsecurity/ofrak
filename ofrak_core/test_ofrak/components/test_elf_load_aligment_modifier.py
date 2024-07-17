import os
import subprocess
from ofrak import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

import pytest

from ofrak import OFRAKContext
from ofrak.core.elf.load_alignment_modifier import main

ASSETS_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "assets/elf"))
OUTPUT_DIR = tempfile.mkdtemp(prefix="ofrak_elf_modifier_out_")
print(OUTPUT_DIR)


@dataclass
class ElfModifierTestCase:
    test_file: str
    label: str
    issue_args: List[Optional[str]] = field(default_factory=lambda: [])
    issue_stdin: Optional[str] = None
    expect_stdout: Optional[str] = None
    expect_return: int = 0

    ld_preload_host: Optional[str] = None


DEFAULT_TEST_INPUT = "Hello world, echo!"

ELF_MODIFIERS_TEST_CASES = [
    ElfModifierTestCase(
        test_file="hello_elf_exec",
        label="pytest_ofrak.elf.fixture (with SCOP) ET_EXEC",
        expect_return=12,
    ),
    ElfModifierTestCase(
        test_file="hello_elf_dyn",
        label="pytest_ofrak.elf.fixture (with SCOP) ET_DYN",
        expect_return=12,
    ),
    ElfModifierTestCase(
        test_file="echo_elf_dyn",
        label="echo@debian-bullseye (with SCOP), ET_DYN",
        issue_args=[f"{DEFAULT_TEST_INPUT}"],
        expect_stdout=f"{DEFAULT_TEST_INPUT}\n",
    ),
    ElfModifierTestCase(
        test_file="libc_elf_dyn_lib",
        label="libc.so.6@debian-bullseye (with SCOP) ET_DYN Library",
        ld_preload_host=f"{ASSETS_DIR}/echo_elf_dyn",
        issue_args=[f"{DEFAULT_TEST_INPUT}"],
        expect_stdout=f"{DEFAULT_TEST_INPUT}\n",
    ),
    ElfModifierTestCase(
        test_file="busybox_elf_exec_noscop",
        label="busybox@ubuntu-5.04 (no SCOP) ET_EXEC, stripped",
        issue_args=["echo", f"{DEFAULT_TEST_INPUT}"],
        expect_stdout=f"{DEFAULT_TEST_INPUT}\n",
    ),
    ElfModifierTestCase(
        test_file="ls_elf_dyn_noscop",
        label="ls@ubuntu-8.10 (no SCOP) ET_DYN, stripped",
        issue_args=["/etc/hostname"],
        expect_stdout=f"/etc/hostname\n",
    ),
    ### Edge case tests
    ElfModifierTestCase(
        test_file="edge-cases/hello_elf_exec_PTLOAD-GAP",
        label="PT_LOAD GAP: pytest_ofrak.elf.fixture (with SCOP) ET_EXEC",
        expect_return=12,
    ),
]


async def verify_modifier_result(test_case: ElfModifierTestCase, output_path: str):
    if test_case.ld_preload_host:
        process = subprocess.run(
            f"LD_PRELOAD={output_path} {test_case.ld_preload_host} "
            f"{' '.join(test_case.issue_args)}",
            shell=True,
            capture_output=True,
            text=True,
        )
    else:
        process = subprocess.run(
            [output_path] + test_case.issue_args, capture_output=True, text=True
        )

    print(process.stdout)
    print(process.stderr)

    assert process.returncode == test_case.expect_return

    if test_case.expect_stdout:
        assert process.stdout == test_case.expect_stdout


class TestElfModifiers:
    @pytest.mark.parametrize(
        "test_case",
        ELF_MODIFIERS_TEST_CASES,
        ids=lambda tc: tc.label,
    )
    async def test_elf_load_alignment_free_space_modifier(
        self, ofrak_context: OFRAKContext, test_case: ElfModifierTestCase, request
    ):
        file_path = os.path.join(ASSETS_DIR, test_case.test_file)
        output_path = f"{OUTPUT_DIR}/{os.path.basename(file_path)}_aligned_free"
        await main(ofrak_context, file_path, output_path)
        os.chmod(output_path, 0o700)
        await verify_modifier_result(test_case, output_path)
