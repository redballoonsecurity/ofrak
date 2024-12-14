import pytest
import requests

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.apk import Apk, ApkPacker, ApkPackerConfig, ApkUnpacker
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

    def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Get a small APK from the internet for testing.
        """
        url = "https://github.com/appium/sample-apps/raw/0e92532585431d3b362c1ff12c65b54936fbe26f/pre-built/ContactManager.apk"
        r = requests.get(url)
        data = r.content
        resource = ofrak_context.create_root_resource("ContactManager.apk", data)
        return resource

    def unpack(self, root_resource: Resource) -> None:
        """
        Unpack, validate that there are children
        """
        root_resource.unpack()
        apk = root_resource.view_as(Apk)
        list_dir = apk.list_dir()
        assert len(list_dir) > 0

    def repack(self, modified_root_resource: Resource) -> None:
        modified_root_resource.run(ApkPacker, self._config)

    def verify(self, repacked_root_resource: Resource) -> None:
        self.unpack(repacked_root_resource)
