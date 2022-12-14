import os
import subprocess
import tempfile

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.p7zip import P7zFilesystem
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"

TARGET_P7ZIP_FILE = "test.7z"
P7ZIP_ENTRY_NAME = "hello_7z_file"


class TestPzUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as d:
            entry_name = os.path.join(d, P7ZIP_ENTRY_NAME)
            target_file = os.path.join(d, TARGET_P7ZIP_FILE)

            # Create a 7z file from  current directory
            with open(entry_name, "wb") as f:
                f.write(INITIAL_DATA)
            command = ["7z", "a", target_file, entry_name]
            subprocess.run(command, check=True, capture_output=True)
            result = await ofrak_context.create_root_resource_from_file(target_file)

        return result

    async def unpack(self, p7zip_resource: Resource) -> None:
        await p7zip_resource.unpack_recursively()

    async def modify(self, unpacked_zip_resource: Resource) -> None:
        p7zip_v = await unpacked_zip_resource.view_as(P7zFilesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await p7zip_v.get_entry(P7ZIP_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, p7zip_resource: Resource) -> None:
        await p7zip_resource.pack_recursively()

    async def verify(self, repacked_p7zip_resource: Resource) -> None:
        resource_data = await repacked_p7zip_resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource_data)
            temp_file.flush()

            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = ["7z", "x", f"-o{temp_flush_dir}", temp_file.name]
                subprocess.run(command, check=True, capture_output=True)
                with open(os.path.join(temp_flush_dir, P7ZIP_ENTRY_NAME), "rb") as f:
                    patched_data = f.read()
                assert patched_data == EXPECTED_DATA
