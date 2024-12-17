import asyncio
import os
import subprocess
import tempfile312 as tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.cpio import CpioFilesystem, CpioPacker, CpioUnpacker
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_CPIO_FILE = "test.cpio"
CPIO_ENTRY_NAME = "hello_cpio_file"


@pytest.mark.skipif_missing_deps([CpioUnpacker, CpioPacker])
class TestCpioUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            wd = os.path.abspath(os.curdir)
            os.chdir(tmpdir)

            # Create a CPIO file from the current directory
            with open(CPIO_ENTRY_NAME, "wb") as f:
                f.write(INITIAL_DATA)
            cmd = ["cpio", "-o"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=tmpdir,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate(CPIO_ENTRY_NAME.encode())
            if proc.returncode:
                raise subprocess.CalledProcessError(
                    returncode=proc.returncode, cmd=cmd, stdout=stdout, stderr=stderr
                )
            result = await ofrak_context.create_root_resource(name=TARGET_CPIO_FILE, data=stdout)

            os.chdir(wd)
            return result

    async def unpack(self, cpio_resource: Resource) -> None:
        await cpio_resource.unpack_recursively()

    async def modify(self, unpacked_cpio_resource: Resource) -> None:
        cpio_v = await unpacked_cpio_resource.view_as(CpioFilesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await cpio_v.get_entry(CPIO_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, cpio_resource: Resource) -> None:
        await cpio_resource.pack_recursively()

    async def verify(self, repacked_cpio_resource: Resource) -> None:
        with tempfile.TemporaryDirectory() as temp_flush_dir:
            cmd = ["cpio", "-id"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=temp_flush_dir,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate(await repacked_cpio_resource.get_data())
            if proc.returncode:
                raise subprocess.CalledProcessError(
                    returncode=proc.returncode, cmd=cmd, stdout=stdout, stderr=stderr
                )
            with open(os.path.join(temp_flush_dir, CPIO_ENTRY_NAME), "rb") as f:
                patched_data = f.read()
            assert patched_data == EXPECTED_DATA
