import os
import subprocess
import tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.seven_zip import SevenZFilesystem, SevenZUnpacker, SevenzPacker
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"

TARGET_SEVEN_ZIP_FILE = "test.7z"
SEVEN_ZIP_ENTRY_NAME = "hello_7z_file"


@pytest.mark.skipif_missing_deps([SevenZUnpacker, SevenzPacker])
class TestPzUnpackModifyPack(UnpackModifyPackPattern):
    def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as d:
            entry_name = os.path.join(d, SEVEN_ZIP_ENTRY_NAME)
            target_file = os.path.join(d, TARGET_SEVEN_ZIP_FILE)

            # Create a 7z file from  current directory
            with open(entry_name, "wb") as f:
                f.write(INITIAL_DATA)
            command = ["7zz", "a", target_file, entry_name]
            subprocess.run(command, check=True, capture_output=True)
            result = ofrak_context.create_root_resource_from_file(target_file)

        return result

    def unpack(self, seven_zip_resource: Resource) -> None:
        seven_zip_resource.unpack_recursively()

    def modify(self, unpacked_zip_resource: Resource) -> None:
        seven_zip_v = unpacked_zip_resource.view_as(SevenZFilesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = seven_zip_v.get_entry(SEVEN_ZIP_ENTRY_NAME)
        child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    def repack(self, seven_zip_resource: Resource) -> None:
        seven_zip_resource.pack_recursively()

    def verify(self, repacked_seven_zip_resource: Resource) -> None:
        resource_data = repacked_seven_zip_resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource_data)
            temp_file.flush()

            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = ["7zz", "x", f"-o{temp_flush_dir}", temp_file.name]
                subprocess.run(command, check=True, capture_output=True)
                with open(os.path.join(temp_flush_dir, SEVEN_ZIP_ENTRY_NAME), "rb") as f:
                    patched_data = f.read()
                assert patched_data == EXPECTED_DATA
