"""
Test APK unpacking, packing, and analysis functionality.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import os
import pytest

from . import ASSETS_DIR
from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.apk import Apk, ApkAnalyzer, ApkAttributes, ApkPacker, ApkPackerConfig, ApkUnpacker
from pytest_ofrak.patterns.unpack_modify_pack import UnpackPackPattern


@pytest.mark.skipif_missing_deps([ApkPacker, ApkUnpacker])
class TestApkUnpackPack(UnpackPackPattern):
    """
    Tag an APK and unpack it, assert that it has contents, repack it, and unpack it again.
    """

    @pytest.fixture(
        params=[None, ApkPackerConfig(sign_apk=False), ApkPackerConfig(sign_apk=True)],
        ids=["no config", "sign_apk false", "sign_apk true"],
        autouse=True,
    )
    def _config_create(self, request):
        self._config = request.param

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Get a small APK for testing.
        """
        return await ofrak_context.create_root_resource_from_file(
            os.path.join(ASSETS_DIR, "ContactManager.apk")
        )

    async def unpack(self, root_resource: Resource) -> None:
        """
        Unpack, validate that there are children
        """
        await root_resource.unpack()
        apk = await root_resource.view_as(Apk)
        list_dir = await apk.list_dir()
        assert len(list_dir) > 0

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ApkPacker, self._config)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await self.unpack(repacked_root_resource)


@pytest.mark.skipif_missing_deps([ApkAnalyzer])
class TestApkAnalyzer:
    """
    Test APK analyzer extracts correct metadata from APK files.
    """

    async def test_analyzer_extracts_all_attributes(self, ofrak_context: OFRAKContext):
        """
        Test that the analyzer extracts all APK attributes correctly from a real APK.
        """
        resource = await ofrak_context.create_root_resource_from_file(
            os.path.join(ASSETS_DIR, "ContactManager.apk")
        )

        # Run the analyzer
        await resource.run(ApkAnalyzer)
        attributes = resource.get_attributes(ApkAttributes)

        assert attributes.package_name == "com.example.android.contactmanager"
        assert attributes.application_name == "Contact Manager"
        assert attributes.version_code == 1
        assert attributes.sdk_version == 5
        assert attributes.target_sdk_version == 5
        assert len(attributes.permissions) == 5
        assert "android.permission.GET_ACCOUNTS" in attributes.permissions
        assert "android.permission.READ_CONTACTS" in attributes.permissions
        assert "android.permission.WRITE_CONTACTS" in attributes.permissions
        assert "android.permission.READ_CALL_LOG" in attributes.permissions
        assert "android.permission.WRITE_CALL_LOG" in attributes.permissions
        assert attributes.launchable_activity == "com.example.android.contactmanager.ContactManager"
