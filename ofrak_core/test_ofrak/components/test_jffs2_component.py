import os
import subprocess
from ofrak import tempfile

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.jffs2 import Jffs2Filesystem
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_JFFS2_FILE = "test.jffs2"
JFFS2_ENTRY_NAME = "hello_jffs2_file"


class TestJffs2UnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            entry_name = os.path.join(tmpdir, JFFS2_ENTRY_NAME)
            parent = os.path.dirname(tmpdir)
            target_file = os.path.join(parent, TARGET_JFFS2_FILE)

            # Create a squashfs file from the current directory
            with open(entry_name, "wb") as f:
                f.write(INITIAL_DATA)
            command = ["mkfs.jffs2", "-r", tmpdir, "-o", target_file]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(target_file)

    async def unpack(self, jffs2_resource: Resource) -> None:
        await jffs2_resource.unpack_recursively()

    async def modify(self, unpacked_zip_resource: Resource) -> None:
        jffs2_v = await unpacked_zip_resource.view_as(Jffs2Filesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await jffs2_v.get_entry(JFFS2_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, jffs2_resource: Resource) -> None:
        await jffs2_resource.pack_recursively()

    async def verify(self, repacked_jffs2_resource: Resource) -> None:
        resource_data = await repacked_jffs2_resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource_data)
            temp_file.close()
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = ["jefferson", "-f", "-d", temp_flush_dir, temp_file.name]
                subprocess.run(command, check=True, capture_output=True)
                with open(os.path.join(temp_flush_dir, JFFS2_ENTRY_NAME), "rb") as f:
                    patched_data = f.read()
                assert patched_data == EXPECTED_DATA
