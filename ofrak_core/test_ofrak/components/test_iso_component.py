import os
from io import BytesIO
from typing import Optional

import pytest
from pycdlib import PyCdlib

from ofrak.resource import Resource
from ofrak.core.iso9660 import (
    ISO9660Entry,
    ISO9660Image,
    ISO9660ImageAttributes,
    ISO9660Packer,
    ISO9660Unpacker,
)
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)


@pytest.mark.skipif_missing_deps([ISO9660Packer, ISO9660Unpacker])
class Iso9660UnpackModifyPackPattern(CompressedFileUnpackModifyPackPattern):
    TEST_ISO_NAME = "test.iso"
    TEST_DIR_NAME = "/TEST"
    TEST_FILE_NAME = os.path.join(TEST_DIR_NAME, "TEST.TXT")
    TEST_SYS_ID = "TestSysID"
    TEST_VOL_ID = "TestVolID"
    TEST_APP_ID = "Test Application"

    EXPECTED_SYS_ID = TEST_SYS_ID
    EXPECTED_VOL_ID = TEST_VOL_ID
    EXPECTED_APP_ID = TEST_APP_ID

    expected_tag = ISO9660Image

    @property
    def expected_image_attributes(self) -> Optional[ISO9660ImageAttributes]:
        return None

    @property
    def expected_file_attributes(self) -> Optional[ISO9660Entry]:
        return None

    async def modify(self, unpacked_root_resource: Resource):
        test_folder = await unpacked_root_resource.get_only_child()
        resource_to_modify = await test_folder.get_only_child()
        new_string_config = StringPatchingConfig(6, "ofrak")
        await resource_to_modify.run(StringPatchingModifier, new_string_config)

    async def verify(self, repacked_root_resource: Resource):
        iso = PyCdlib()
        iso.open_fp(BytesIO(await repacked_root_resource.get_data()))

        extracted = BytesIO()
        if iso.has_joliet():
            iso.get_file_from_iso_fp(extracted, joliet_path=self.TEST_FILE_NAME)
        else:
            iso.get_file_from_iso_fp(extracted, iso_path=self.TEST_FILE_NAME + ";1")

        iso.close()

        if self.expected_image_attributes:
            attributes = await repacked_root_resource.analyze(ISO9660ImageAttributes)
            assert attributes == self.expected_image_attributes

        await repacked_root_resource.unpack()
        await repacked_root_resource.summarize_tree()

        repacked_iso_resource = await repacked_root_resource.view_as(ISO9660Image)

        for desc in await repacked_iso_resource.get_entries():
            await repacked_iso_resource.get_file(desc.Path)


class TestIso9660UnpackModifyPack(Iso9660UnpackModifyPackPattern):
    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        iso = PyCdlib()
        iso.new(
            interchange_level=3,
            sys_ident=self.TEST_SYS_ID,
            vol_ident=self.TEST_VOL_ID,
        )
        iso.add_directory(self.TEST_DIR_NAME)
        iso.add_fp(BytesIO(self.INITIAL_DATA), len(self.INITIAL_DATA), self.TEST_FILE_NAME + ";1")
        iso.write(os.path.join(tmpdir, self.TEST_ISO_NAME))
        self._test_file = os.path.join(tmpdir, self.TEST_ISO_NAME)


class TestJolietUnpackModifyPack(Iso9660UnpackModifyPackPattern):
    TEST_DIR_NAME = "/test"
    TEST_FILE_NAME = os.path.join(TEST_DIR_NAME, "test.txt")

    expected_image_attributes = ISO9660ImageAttributes(
        interchange_level=3,
        volume_identifier=Iso9660UnpackModifyPackPattern.TEST_VOL_ID,
        system_identifier=Iso9660UnpackModifyPackPattern.TEST_SYS_ID,
        app_identifier=Iso9660UnpackModifyPackPattern.TEST_APP_ID,
        extended_attributes=False,
        has_joliet=True,
        joliet_level=3,
        has_rockridge=False,
        has_udf=False,
        has_eltorito=False,
    )

    expected_file_attributes = ISO9660Entry(
        name=os.path.basename(Iso9660UnpackModifyPackPattern.TEST_FILE_NAME),
        path=Iso9660UnpackModifyPackPattern.TEST_FILE_NAME,
        is_dir=False,
        is_file=True,
        is_symlink=False,
        is_dot=False,
        is_dotdot=False,
        iso_version=1,
    )

    @pytest.fixture(autouse=True)
    def create_test_file(self, tmpdir):
        initial_data = self.INITIAL_DATA
        test_dir = str(self.TEST_DIR_NAME)
        test_file = str(self.TEST_FILE_NAME)

        iso = PyCdlib()
        iso.new(
            interchange_level=3,
            joliet=3,
            sys_ident=self.TEST_SYS_ID,
            vol_ident=self.TEST_VOL_ID,
            app_ident_str=self.TEST_APP_ID,
        )

        iso.add_directory(test_dir.upper(), joliet_path=test_dir)
        iso.add_fp(
            BytesIO(initial_data),
            len(initial_data),
            test_file.upper() + ";1",
            joliet_path=test_file,
        )
        iso.write(os.path.join(tmpdir, self.TEST_ISO_NAME))
        self._test_file = os.path.join(tmpdir, self.TEST_ISO_NAME)
