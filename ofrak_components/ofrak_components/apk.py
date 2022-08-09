import os
import subprocess
import tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError
from typing import Type

from ofrak import Identifier, Packer, Unpacker, Resource
from ofrak.component.identifier import IdentifierError
from ofrak.component.packer import PackerError
from ofrak.component.unpacker import UnpackerError
from ofrak.core import (
    GenericBinary,
    File,
    Folder,
    format_called_process_error,
    MagicMimeIdentifier,
    Magic,
)
from ofrak.model.component_model import ComponentConfig
from ofrak_components.zip import ZipArchive
from ofrak_type.range import Range


class Apk(ZipArchive):
    pass


class ApkUnpacker(Unpacker[None]):
    """
    Decode Android APK files.

    This unpacker is a wrapper for `apktool`. See <https://ibotpeaches.github.io/Apktool/>.
    """

    targets = (Apk,)
    children = (File, Folder)

    async def unpack(self, resource: Resource, config=None):
        """
        Decode Android APK files.

        :param resource:
        :param config:
        """
        apk = await resource.view_as(Apk)
        data = await resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(data)
            temp_file.flush()
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = [
                    "apktool",
                    "decode",
                    "--output",
                    temp_flush_dir,
                    "--force",
                    temp_file.name,
                ]
                _run_command(command, UnpackerError)
                await apk.initialize_from_disk(temp_flush_dir)


@dataclass
class ApkPackerConfig(ComponentConfig):
    sign_apk: bool


class ApkPacker(Packer[ApkPackerConfig]):
    """
    Pack decoded APK resources into an APK.

    This unpacker is a wrapper for two tools:

    - `apktool` repacks the APK resources. See <https://ibotpeaches.github.io/Apktool/>.
    - `uber-apk-signer` signs the packed APK file. See
    <https://github.com/patrickfav/uber-apk-signer>.

    Another helpful overview of the process: <https://github.com/vaibhavpandeyvpz/apkstudio>.
    """

    targets = (Apk,)

    async def pack(
        self, resource: Resource, config: ApkPackerConfig = ApkPackerConfig(sign_apk=True)
    ):
        """
        Pack disassembled APK resources into an APK.

        :param resource:
        :param config:
        """
        apk = await resource.view_as(Apk)
        temp_flush_dir = await apk.flush_to_disk()
        apk_suffix = ".apk"
        with tempfile.NamedTemporaryFile(suffix=apk_suffix) as temp_apk:
            command = ["apktool", "build", "--force-all", temp_flush_dir, "--output", temp_apk.name]
            _run_command(command, PackerError)
            if not config.sign_apk:
                # Close the file handle and reopen, to avoid observed situations where temp.read()
                # was not returning data
                with open(temp_apk.name, "rb") as file_handle:
                    new_data = file_handle.read()
            else:
                with tempfile.TemporaryDirectory() as signed_apk_temp_dir:
                    command = [
                        "java",
                        "-jar",
                        "/usr/local/bin/uber-apk-signer.jar",
                        "--apks",
                        temp_apk.name,
                        "--out",
                        signed_apk_temp_dir,
                        "--allowResign",
                    ]
                    _run_command(command, PackerError)
                    signed_apk_filename = (
                        os.path.basename(temp_apk.name)[: -len(apk_suffix)]
                        + "-aligned-debugSigned.apk"
                    )
                    signed_file_name = os.path.join(
                        signed_apk_temp_dir,
                        signed_apk_filename,
                    )
                    with open(signed_file_name, "rb") as file_handle:
                        new_data = file_handle.read()
            assert len(new_data) != 0
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


class ApkIdentifier(Identifier):
    targets = (File, GenericBinary)

    async def identify(self, resource: Resource, config=None) -> None:
        await resource.run(MagicMimeIdentifier)
        magic = resource.get_attributes(Magic)
        if magic is not None and magic.mime in ["application/java-archive", "application/zip"]:
            with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
                temp_file.write(await resource.get_data())
                temp_file.flush()

                command = ["unzip", "-l", temp_file.name]
                filenames = _run_command(command, IdentifierError)

                if b"androidmanifest.xml" in filenames.lower():
                    resource.add_tag(Apk)


def _run_command(command, error_type: Type[Exception]):
    try:
        run = subprocess.run(command, check=True, capture_output=True)
        return run.stdout
    except CalledProcessError as error:
        raise error_type(format_called_process_error(error))
