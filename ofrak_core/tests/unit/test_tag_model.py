from ofrak.core import GenericBinary


def test_tag_model_repr(capsys):
    print(GenericBinary, end="")
    out, _ = capsys.readouterr()
    assert out == "GenericBinary"
