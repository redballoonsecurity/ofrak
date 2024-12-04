import os
import subprocess
from ofrak import tempfile

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.cpio import CpioFilesystem
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_CPIO_FILE = "test.cpio"
CPIO_ENTRY_NAME = "hello_cpio_file"


class TestCpioUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            wd = os.path.abspath(os.curdir)
            os.chdir(tmpdir)

            # Create a CPIO file from the current directory
            with open(CPIO_ENTRY_NAME, "wb") as f:
                f.write(INITIAL_DATA)
            command = f"find {CPIO_ENTRY_NAME} -print | cpio -o > {TARGET_CPIO_FILE}"
            subprocess.run(command, check=True, capture_output=True, shell=True)
            result = await ofrak_context.create_root_resource_from_file(TARGET_CPIO_FILE)

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
        resource_data = await repacked_cpio_resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource_data)
            temp_file.close()
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = f"(cd {temp_flush_dir} && cpio -id < {temp_file.name})"
                subprocess.run(command, check=True, capture_output=True, shell=True)
                with open(os.path.join(temp_flush_dir, CPIO_ENTRY_NAME), "rb") as f:
                    patched_data = f.read()
                assert patched_data == EXPECTED_DATA
