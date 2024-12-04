import json
import os

import pytest

from ofrak.license import Agreement, LicenseDataType, read_license_file


class TestAgreement:
    @pytest.mark.parametrize(
        "license_data", ({"license_type": "Community License"}, {"license_type": "Pro License"})
    )
    def test_get_agreement(self, license_data: LicenseDataType):
        assert isinstance(Agreement.get_agreement(license_data), str)


@pytest.fixture
def license_file(tmpdir) -> str:
    file_path = os.path.join(tmpdir, "license.json")
    with open(file_path, "w") as f:
        json.dump([{"a": "b", "b": None}], f)
    return file_path


def test_read_license_file(license_file: str):
    license_data, abs_path = read_license_file(license_file)
    assert isinstance(license_data, dict)
    assert os.path.exists(abs_path)
