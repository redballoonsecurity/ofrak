import os
import tempfile312 as tempfile
from abc import ABC
from typing import Type, List

import pytest

from ofrak import OFRAKContext, Resource, ResourceAttributes
from ofrak.core import FilesystemRoot, StringPatchingConfig, StringPatchingModifier
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource import RV
from ofrak.core.cpio import CpioFilesystem, CpioArchiveType, CpioPacker, CpioUnpacker
from ofrak.core.tar import TarArchive, TarPacker, TarUnpacker
from ofrak.core.zip import ZipArchive, ZipPacker, ZipUnpacker
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

CHILD_TEXT = "Hello World\n"
SUBCHILD_TEXT = "Goodbye World\n"

CHILD_TEXTFILE_NAME = "hello.txt"
CHILD_FOLDER = "test_folder"
SUBCHILD_TEXTFILE_NAME = "goodbye.txt"
SUBCHILD_FOLDER = "test_subfolder"

NUM_FILES = 2
NUM_FOLDERS = 2

EXPECTED_CHILD_TEXT = "Hello OFrak\n"
EXPECTED_SUBCHILD_TEXT = "Goodbye OFrak\n"

TAGS = [
    pytest.param(ZipArchive, [], marks=pytest.mark.skipif_missing_deps([ZipUnpacker, ZipPacker])),
    pytest.param(TarArchive, [], marks=pytest.mark.skipif_missing_deps([TarUnpacker, TarPacker])),
    pytest.param(
        CpioFilesystem,
        [AttributesType[CpioFilesystem](CpioArchiveType.BINARY)],
        marks=pytest.mark.skipif_missing_deps([CpioUnpacker, CpioPacker]),
    ),
]


@pytest.mark.parametrize("tag, attr", TAGS)
class FilesystemPattern(UnpackModifyPackPattern, ABC):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as temp_dir:
            child_folder = os.path.join(temp_dir, CHILD_FOLDER)
            child_file = os.path.join(temp_dir, CHILD_TEXTFILE_NAME)
            subchild_file = os.path.join(child_folder, SUBCHILD_TEXTFILE_NAME)
            subchild_folder = os.path.join(child_folder, SUBCHILD_FOLDER)

            if not os.path.exists(child_folder):
                os.mkdir(child_folder)
            if not os.path.exists(subchild_folder):
                os.mkdir(subchild_folder)

            with open(child_file, "w") as f:
                f.write(CHILD_TEXT)
            with open(subchild_file, "w") as f:
                f.write(SUBCHILD_TEXT)

            resource = await ofrak_context.create_root_resource(
                name=temp_dir, data=b"", tags=[FilesystemRoot]
            )
            await resource.save()
            filesystem_view = await resource.view_as(FilesystemRoot)
            await filesystem_view.initialize_from_disk(temp_dir)
            resource.add_tag(self.tag)
            for attr in self.attr:
                resource.add_attributes(attr)
            await resource.save()
            await resource.pack_recursively()

            return resource

    async def unpack(self, resource: Resource) -> None:
        await resource.unpack()

    async def repack(self, resource: Resource) -> None:
        await resource.pack_recursively()

    @pytest.fixture(autouse=True)
    def add_tag(self, tag: Type[RV], attr: List[ResourceAttributes]):
        self.tag = tag
        self.attr = attr


class TestFilesystemAddFile(FilesystemPattern):
    #  TODO: add file attrs and check
    async def modify(self, unpacked_resource: Resource) -> None:
        print(await unpacked_resource.summarize_tree())
        unpacked_resource_view = await unpacked_resource.view_as(self.tag)
        await unpacked_resource_view.add_file("test_folder/test.txt", b"test")
        print(await unpacked_resource.summarize_tree())

    async def verify(self, repacked_zip_resource: Resource) -> None:
        await repacked_zip_resource.unpack()
        print(await repacked_zip_resource.summarize_tree())
        repacked_zip_resource_view = await repacked_zip_resource.view_as(self.tag)
        new_file = await repacked_zip_resource_view.get_entry("test_folder/test.txt")
        assert new_file is not None
        assert await new_file.resource.get_data() == b"test"


class TestFilesystemRemoveFile(FilesystemPattern):
    async def modify(self, unpacked_resource: Resource) -> None:
        unpacked_resource_view = await unpacked_resource.view_as(self.tag)
        await unpacked_resource_view.remove_file("test_folder/goodbye.txt")

    async def verify(self, repacked_resource: Resource) -> None:
        await repacked_resource.unpack()
        repacked_resource_view = await repacked_resource.view_as(self.tag)
        old_file = await repacked_resource_view.get_entry("test_folder/goodbye.txt")
        assert old_file is None


class TestFilesystemComponent(FilesystemPattern):
    async def modify(self, resource: Resource) -> None:
        zip_archive = await resource.view_as(self.tag)
        child_text_string_config = StringPatchingConfig(6, "OFrak")
        child_textfile = await zip_archive.get_entry("hello.txt")
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

        subchild_text_string_config = StringPatchingConfig(8, "OFrak")
        subchild_textfile = await zip_archive.get_entry("test_folder/goodbye.txt")
        await subchild_textfile.resource.run(StringPatchingModifier, subchild_text_string_config)

    async def verify(self, resource: Resource) -> None:
        await resource.unpack()
        resource_view = await resource.view_as(self.tag)
        flush_tmp = await resource_view.flush_to_disk()

        dirs = []
        files_dict = {}
        for root, directories, files in os.walk(flush_tmp):
            for d in directories:
                dirs.append(d)
            for f in files:
                with open(os.path.join(root, f)) as fh:
                    files_dict[f] = fh.read()
        assert len(dirs) == NUM_FOLDERS
        assert len(files_dict.keys()) == NUM_FILES

        assert set(dirs) == {"test_folder", "test_subfolder"}
        assert sorted(list(files_dict.keys())) == sorted(["goodbye.txt", "hello.txt"])

        assert files_dict["hello.txt"] == EXPECTED_CHILD_TEXT
        assert files_dict["goodbye.txt"] == EXPECTED_SUBCHILD_TEXT
