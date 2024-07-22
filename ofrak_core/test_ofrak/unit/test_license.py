import pytest

from ofrak.license import Agreement, LicenseDataType


class TestAgreement:
    @pytest.mark.parametrize(
        "license_data", ({"license_type": "Community License"}, {"license_type": "Pro License"})
    )
    def test_get_agreement(self, license_data: LicenseDataType):
        assert isinstance(Agreement.get_agreement(license_data), str)
