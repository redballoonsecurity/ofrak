"""
This module tests the license agreement and license file reading functionality.
"""
import json
import os

import pytest

from ofrak.license import Agreement, LicenseDataType, read_license_file


class TestAgreement:
    """
    This test verifies that the Agreement class can correctly retrieve agreements based on license data.

    This test verifies that:
    - The get_agreement method returns a string for different license types
    """

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
    """
    This test verifies that the read_license_file function correctly reads and parses license files.

    This test verifies that:
    - The function returns parsed license data as a dictionary
    - The function returns the absolute path of the file
    """
    license_data, abs_path = read_license_file(license_file)
    assert isinstance(license_data, dict)
    assert os.path.exists(abs_path)
