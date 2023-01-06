from ofrak.core import MemoryRegion


def test_memory_region_str():
    memory_region = MemoryRegion(0x100, 0x20)
    assert str(memory_region) == "MemoryRegion(0x100-0x120)"


def test_memory_region_hash():
    region_a = MemoryRegion(0x40, 0x10)
    region_b = MemoryRegion(0x40, 0x5)
    region_c = MemoryRegion(0x100, 0x5)
    memory_bank = {region_a, region_b}
    assert region_a in memory_bank
    assert region_b in memory_bank
    assert region_c not in memory_bank
