from ofrak.core import X86_64ElfRelaInfo


def test_type_mask():
    """
    Sanity check that X86_64ElfRelaInfo.type_mask applies a type mask.
    """
    value = 0xFFFFFFFF00000008
    assert X86_64ElfRelaInfo.type_mask(value) == X86_64ElfRelaInfo.R_X86_64_RELATIVE.value
