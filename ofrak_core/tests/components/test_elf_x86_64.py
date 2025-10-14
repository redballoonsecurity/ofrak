"""
This module tests the x86_64 ELF components.
"""

from ofrak.core import X86_64ElfRelaInfo


def test_type_mask():
    """
    Sanity check that X86_64ElfRelaInfo.type_mask applies a type mask.

    This test verifies that:
    - The type_mask method correctly extracts the type portion of a value
    - The extracted type matches the expected R_X86_64_RELATIVE value
    """
    value = 0xFFFFFFFF00000008
    assert X86_64ElfRelaInfo.type_mask(value) == X86_64ElfRelaInfo.R_X86_64_RELATIVE.value
