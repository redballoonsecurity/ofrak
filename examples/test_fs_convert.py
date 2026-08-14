import os
import tempfile312 as tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.core.cpio import CpioArchiveType, CpioFilesystem
from ofrak.core.filesystem import FilesystemRoot
from ofrak.core.tar import TarArchive
from ofrak.model.viewable_tag_model import AttributesType

from examples.fs_convert import convert_filesystem, FORMATS, FORMAT_DEFAULT_VIEWS

FILES = {
    "README.md": b"# My Project\nThis is a test project.\n",
    "src/main.c": b"#include <stdio.h>\nint main() { return 0; }\n",
    "src/util/helper.c": b"void help() {}\n",
    "src/util/helper.h": b"#pragma once\nvoid help();\n",
    "data/config.json": b'{"key": "value", "count": 42}\n',
    "docs/guide.txt": b"Step 1: Build\nStep 2: Run\nStep 3: Profit\n",
}
EMPTY_DIRS = ["data/empty"]

# Source format, source attrs, target format name
CONVERSIONS = [
    pytest.param(TarArchive, [], "zip", id="tar-to-zip"),
    pytest.param(TarArchive, [], "cpio", id="tar-to-cpio"),
    pytest.param(
        CpioFilesystem,
        [AttributesType[CpioFilesystem](CpioArchiveType.NEW_ASCII)],
        "tar",
        id="cpio-to-tar",
    ),
    pytest.param(
        CpioFilesystem,
        [AttributesType[CpioFilesystem](CpioArchiveType.NEW_ASCII)],
        "zip",
        id="cpio-to-zip",
    ),
    pytest.param(TarArchive, [], "tar", id="tar-to-tar"),
]


def build_test_tree(base_dir: str) -> None:
    for rel_path, content in FILES.items():
        full_path = os.path.join(base_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(content)
    for rel_dir in EMPTY_DIRS:
        os.makedirs(os.path.join(base_dir, rel_dir), exist_ok=True)


async def create_source_archive(ofrak_context: OFRAKContext, source_tag, source_attrs) -> str:
    temp_dir = tempfile.mkdtemp()
    tree_dir = os.path.join(temp_dir, "tree")
    os.makedirs(tree_dir)
    build_test_tree(tree_dir)

    resource = await ofrak_context.create_root_resource(
        name=tree_dir, data=b"", tags=[FilesystemRoot]
    )
    await resource.save()
    fs_view = await resource.view_as(FilesystemRoot)
    await fs_view.initialize_from_disk(tree_dir)
    resource.add_tag(source_tag)
    for attr in source_attrs:
        resource.add_attributes(attr)
    await resource.save()
    await resource.pack_recursively()

    archive_path = os.path.join(temp_dir, "source_archive")
    await resource.flush_data_to_disk(archive_path)
    return archive_path


async def verify_filesystem(
    ofrak_context: OFRAKContext, output_path: str, target_format: str
) -> None:
    root = await ofrak_context.create_root_resource_from_file(output_path)
    default_view = FORMAT_DEFAULT_VIEWS.get(target_format)
    if default_view is not None:
        root.add_view(default_view)
    else:
        root.add_tag(FORMATS[target_format])
    await root.save()
    await root.unpack_recursively()
    fs_view = await root.view_as(FilesystemRoot)

    for rel_path, expected_content in FILES.items():
        entry = await fs_view.get_entry(rel_path)
        assert entry is not None, f"Missing file: {rel_path}"
        data = await entry.resource.get_data()
        assert (
            data == expected_content
        ), f"Content mismatch for {rel_path}: expected {expected_content!r}, got {data!r}"

    for rel_dir in EMPTY_DIRS:
        entry = await fs_view.get_entry(rel_dir)
        assert entry is not None, f"Missing directory: {rel_dir}"


@pytest.mark.parametrize("source_tag,source_attrs,target_format", CONVERSIONS)
async def test_fs_convert(ofrak_context, source_tag, source_attrs, target_format, tmp_path):
    source_path = await create_source_archive(ofrak_context, source_tag, source_attrs)
    output_path = str(tmp_path / "output")
    await convert_filesystem(ofrak_context, source_path, output_path, target_format)

    assert os.path.exists(output_path)
    assert os.path.getsize(output_path) > 0

    await verify_filesystem(ofrak_context, output_path, target_format)
