from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Mapping

import pytest

from ofrak_patch_maker.toolchain.utils import generate_arm_stubs, NULL_DATA

from ofrak_patch_maker.toolchain.model import Segment
from ofrak_type import MemoryPermissions


@dataclass
class GenerateArmStubsTestCase:
    func_names: Mapping[str, int]
    thumb: bool

    def get_expected_segments(self, stub_path: str) -> Tuple[Segment, Segment]:
        func_name = Path(stub_path).stem
        vm_address = self.func_names[func_name]
        return Segment(".text", vm_address, 0, False, 0, MemoryPermissions.RX), NULL_DATA


@pytest.mark.parametrize(
    "test_case",
    [
        GenerateArmStubsTestCase({}, True),
        GenerateArmStubsTestCase({}, False),
        GenerateArmStubsTestCase({"hello_world": 0x10000}, True),
        GenerateArmStubsTestCase({"hello_world": 0x10000}, False),
    ],
)
def test_generate_arm_stubs(test_case: GenerateArmStubsTestCase, tmp_path):
    """
    Test that generate_arm_stubs correctly generates stubs with the correct segments.
    """
    stubs = generate_arm_stubs(test_case.func_names, str(tmp_path), test_case.thumb)
    assert len(stubs) == len(test_case.func_names)
    for stub_file, segments in stubs.items():
        expected_segments = test_case.get_expected_segments(stub_file)
        assert expected_segments == segments
