from gzip import GzipFile as _GzipFile

import pytest
from io import BytesIO


@pytest.fixture
def test_file(tmpdir):
    d = tmpdir.mkdir("gzip")
    fh = d.join("hello.gz")
    result = BytesIO()
    with _GzipFile(fileobj=result, mode="w") as gzip_file:
        gzip_file.write(b"hello world")
    fh.write_binary(result.getvalue())

    return fh.realpath()


def test_unpack_pack_unpack(ofrak_context, test_file):
    root_resource = ofrak_context.create_root_resource_from_file(test_file)

    root_resource.unpack()
    children1 = root_resource.get_children()
    assert 1 == len(list(children1))

    # Children should be deleted after packing
    root_resource.pack()
    children2 = root_resource.get_children()
    assert 0 == len(list(children2))

    # Resource should now be ready to be unpacked again
    root_resource.unpack()
    children3 = root_resource.get_children()
    assert 1 == len(list(children3))
