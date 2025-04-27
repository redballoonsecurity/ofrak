import os
import subprocess

import pytest
import tempfile312 as tempfile

from ofrak import OFRAKContext
from ofrak.core.cpio import CpioFilesystem, CpioPacker, CpioUnpacker
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from ofrak.resource import Resource
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_CPIO_FILE = "test.cpio"
CPIO_ENTRY_NAME = "hello_cpio_file"


@pytest.mark.skipif_missing_deps([CpioUnpacker, CpioPacker])
class TestCpioUnpackModifyPack(UnpackModifyPackPattern):
    def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            wd = os.path.abspath(os.curdir)
            os.chdir(tmpdir)

            # Create a CPIO file from the current directory
            with open(CPIO_ENTRY_NAME, "wb") as f:
                f.write(INITIAL_DATA)
            cmd = ["cpio", "-o"]
            proc = subprocess.run(
                cmd,
                cwd=tmpdir,
                input=CPIO_ENTRY_NAME.encode(),  # Pass the input directly
                capture_output=True,
            )
            if proc.returncode:
                raise subprocess.CalledProcessError(
                    returncode=proc.returncode, cmd=cmd, output=proc.stdout, stderr=proc.stderr
                )
            result = ofrak_context.create_root_resource(name=TARGET_CPIO_FILE, data=proc.stdout)

            os.chdir(wd)
            return result

    def unpack(self, cpio_resource: Resource) -> None:
        cpio_resource.unpack_recursively()

    def modify(self, unpacked_cpio_resource: Resource) -> None:
        cpio_v = unpacked_cpio_resource.view_as(CpioFilesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = cpio_v.get_entry(CPIO_ENTRY_NAME)
        child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    def repack(self, cpio_resource: Resource) -> None:
        cpio_resource.pack_recursively()

    def verify(self, repacked_cpio_resource: Resource) -> None:
        with tempfile.TemporaryDirectory() as temp_flush_dir:
            cmd = ["cpio", "-id"]
            proc = subprocess.run(
                cmd,
                cwd=temp_flush_dir,
                input=repacked_cpio_resource.get_data(),
                capture_output=True,
            )
            if proc.returncode:
                raise subprocess.CalledProcessError(
                    returncode=proc.returncode, cmd=cmd, output=proc.stdout, stderr=proc.stderr
                )
            with open(os.path.join(temp_flush_dir, CPIO_ENTRY_NAME), "rb") as f:
                patched_data = f.read()
            assert patched_data == EXPECTED_DATA
