import asyncio
import os
import pathlib
import sys
import tempfile
from subprocess import CalledProcessError
from dataclasses import dataclass

from ofrak.core.filesystem import File, Folder

from ofrak.component.packer import Packer

from ofrak.resource import Resource

from ofrak.component.unpacker import Unpacker
from ofrak.component.identifier import Identifier

from ofrak.model.component_model import ComponentConfig, ComponentExternalTool
from ofrak.core.zip import ZipArchive, UNZIP_TOOL
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import Magic, MagicMimeIdentifier
from ofrak_type.range import Range


APKTOOL = ComponentExternalTool("apktool", "https://ibotpeaches.github.io/Apktool/", "--help")
JAVA = ComponentExternalTool(
    "java",
    "https://openjdk.org/projects/jdk/11/",
    "--help",
    apt_package="openjdk-11-jdk",
    brew_package="openjdk@11",
)


class _UberApkSignerTool(ComponentExternalTool):
    if sys.platform.startswith("win32"):
        # Windows: look in Program Files (x86)
        JAR_PATH = os.path.join(
            "C:", "Program Files (x86)", "uber-apk-signer", "uber-apk-signer.jar"
        )
    elif sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        # Linux, Mac OSX: look in usr/local/bin
        JAR_PATH = os.path.join(os.path.sep, "usr", "local", "bin", "uber-apk-signer.jar")
    else:
        # All other platforms: look in home dir
        JAR_PATH = os.path.join(pathlib.Path.home(), "uber-apk-signer.jar")

    def __init__(self):
        super().__init__(
            _UberApkSignerTool.JAR_PATH,
            "https://github.com/patrickfav/uber-apk-signer",
            install_check_arg="",
        )

    async def is_tool_installed(self) -> bool:
        if not os.path.exists(_UberApkSignerTool.JAR_PATH):
            return False

        try:
            cmd = [
                "java",
                "-jar",
                _UberApkSignerTool.JAR_PATH,
                "--help",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            returncode = await proc.wait()
        except FileNotFoundError:
            return False

        return 0 == returncode


UBER_APK_SIGNER = _UberApkSignerTool()


class Apk(ZipArchive):
    pass


class ApkUnpacker(Unpacker[None]):
    """
    Decode Android APK files.

    This unpacker is a wrapper for `apktool`. See <https://ibotpeaches.github.io/Apktool/>.
    """

    targets = (Apk,)
    children = (File, Folder)
    external_dependencies = (APKTOOL,)

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
                cmd = [
                    "apktool",
                    "decode",
                    "--output",
                    temp_flush_dir,
                    "--force",
                    temp_file.name,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                )
                returncode = await proc.wait()
                if proc.returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)
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
    external_dependencies = (APKTOOL, JAVA, UBER_APK_SIGNER)

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
            apk_cmd = [
                "apktool",
                "build",
                "--force-all",
                temp_flush_dir,
                "--output",
                temp_apk.name,
            ]
            apk_proc = await asyncio.create_subprocess_exec(
                *apk_cmd,
            )
            apk_returncode = await apk_proc.wait()
            if apk_proc.returncode:
                raise CalledProcessError(returncode=apk_returncode, cmd=apk_cmd)
            if not config.sign_apk:
                # Close the file handle and reopen, to avoid observed situations where temp.read()
                # was not returning data
                with open(temp_apk.name, "rb") as file_handle:
                    new_data = file_handle.read()
            else:
                with tempfile.TemporaryDirectory() as signed_apk_temp_dir:
                    java_cmd = [
                        "java",
                        "-jar",
                        _UberApkSignerTool.JAR_PATH,
                        "--apks",
                        temp_apk.name,
                        "--out",
                        signed_apk_temp_dir,
                        "--allowResign",
                    ]
                    java_proc = await asyncio.create_subprocess_exec(
                        *java_cmd,
                    )
                    java_returncode = await java_proc.wait()
                    if java_proc.returncode:
                        raise CalledProcessError(returncode=java_returncode, cmd=java_cmd)
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
    external_dependencies = (UNZIP_TOOL,)

    async def identify(self, resource: Resource, config=None) -> None:
        await resource.run(MagicMimeIdentifier)
        magic = resource.get_attributes(Magic)
        if magic is not None and magic.mime in ["application/java-archive", "application/zip"]:
            with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
                temp_file.write(await resource.get_data())
                temp_file.flush()
                unzip_cmd = [
                    "unzip",
                    "-l",
                    temp_file.name,
                ]
                unzip_proc = await asyncio.create_subprocess_exec(
                    *unzip_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await unzip_proc.communicate()
                if unzip_proc.returncode:
                    raise CalledProcessError(returncode=unzip_proc.returncode, cmd=unzip_cmd)

                if b"androidmanifest.xml" in stdout.lower():
                    resource.add_tag(Apk)
