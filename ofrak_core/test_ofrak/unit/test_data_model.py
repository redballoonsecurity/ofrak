from ofrak_type.range import Range

from ofrak.model.data_model import DataPatch


def test_data_patch_repr(capsys):
    data_patch = DataPatch(Range(0x100, 0x101), b"\xfe\xed\xfa\xce", b"\xff")
    print(data_patch, end="")
    out, _ = capsys.readouterr()
    assert out == "DataPatch(feedface, Range(0x100, 0x101), 1)"
