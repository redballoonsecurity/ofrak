import asyncio
import os
import pathlib
import re
import sys
import tempfile312 as tempfile
from subprocess import CalledProcessError
from dataclasses import dataclass
from typing import List, Optional

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.filesystem import File, Folder
from ofrak.core.java import JavaArchive
from ofrak.core.magic import MagicMimePattern
from ofrak.core.zip import ZipArchive, UNZIP_TOOL
from ofrak.model.component_model import ComponentConfig, ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak_type.range import Range

APKTOOL = ComponentExternalTool(
    "apktool",
    "https://ibotpeaches.github.io/Apktool/",
    "-version",
    choco_package="apktool",
)
JAVA = ComponentExternalTool(
    "java",
    "https://openjdk.org/projects/jdk/17/",
    "-help",
    apt_package="openjdk-17-jdk",
    brew_package="openjdk@17",
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

AAPT = ComponentExternalTool(
    "aapt",
    "https://developer.android.com/tools/releases/build-tools",
    "version",
    apt_package="android-sdk-build-tools",
)


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ApkAttributes(ResourceAttributes):
    """
    Attributes extracted from an Android APK package using aapt.

    :param package_name: The unique package identifier (e.g., 'com.example.app')
    :param application_name: The human-readable application name
    :param version_code: Integer version code for internal versioning
    :param sdk_version: Minimum SDK version required to run the app
    :param target_sdk_version: Target SDK version the app was built for
    :param permissions: List of Android permissions requested by the app
    :param launchable_activity: Main activity that launches the app
    """

    package_name: str
    application_name: Optional[str]
    version_code: int
    sdk_version: int
    target_sdk_version: int
    permissions: List[str]
    launchable_activity: Optional[str]


class Apk(ZipArchive):
    pass


class ApkAnalyzer(Analyzer[None, ApkAttributes]):
    """
    Analyzes Android APK packages using aapt to extract package metadata including package name,
    application name, version information, SDK requirements, permissions, and launchable activity.
    The analyzer parses structured output from aapt dump badging to extract key APK attributes
    useful for understanding app identity, requirements, and capabilities. Use when you need to
    identify an APK's package name, determine version and SDK requirements, audit requested
    permissions, or find the main activity without unpacking the entire APK.
    """

    id = b"ApkAnalyzer"
    targets = (Apk,)
    outputs = (ApkAttributes,)
    external_dependencies = (AAPT,)

    async def analyze(self, resource: Resource, config=None) -> ApkAttributes:
        async with resource.temp_to_disk(suffix=".apk") as temp_path:
            cmd = ["aapt", "dump", "badging", temp_path]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode:
                raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

            output = stdout.decode("utf-8")
            return self._parse_aapt_output(output)

    def _parse_aapt_output(self, output: str) -> ApkAttributes:
        """
        Parse aapt dump badging output to extract APK attributes.

        :param output: Raw output from aapt dump badging command

        :return: Parsed APK attributes
        """
        lines = output.split("\n")

        package_name = None
        version_code = None
        sdk_version = None
        target_sdk_version = None
        application_name = None
        launchable_activity = None
        permissions = []

        for line in lines:
            # Parse package line: package: name='com.example' versionCode='123' ...
            if line.startswith("package:"):
                package_match = re.search(r"name='([^']+)'", line)
                if package_match:
                    package_name = package_match.group(1)

                version_code_match = re.search(r"versionCode='([^']+)'", line)
                if version_code_match:
                    version_code = int(version_code_match.group(1))

            # Parse sdkVersion line: sdkVersion:'23'
            elif line.startswith("sdkVersion:"):
                sdk_match = re.search(r"sdkVersion:'(\d+)'", line)
                if sdk_match:
                    sdk_version = int(sdk_match.group(1))

            # Parse targetSdkVersion line: targetSdkVersion:'30'
            elif line.startswith("targetSdkVersion:"):
                target_match = re.search(r"targetSdkVersion:'(\d+)'", line)
                if target_match:
                    target_sdk_version = int(target_match.group(1))

            # Parse application-label line: application-label:'MyApp'
            elif line.startswith("application-label:") and not line.startswith(
                "application-label-"
            ):
                label_match = re.search(r"application-label:'([^']+)'", line)
                if label_match:
                    application_name = label_match.group(1)

            # Parse launchable-activity line: launchable-activity: name='com.example.MainActivity' ...
            elif line.startswith("launchable-activity:"):
                activity_match = re.search(r"name='([^']+)'", line)
                if activity_match:
                    launchable_activity = activity_match.group(1)

            # Parse uses-permission line: uses-permission: name='android.permission.INTERNET'
            elif line.startswith("uses-permission:"):
                permission_match = re.search(r"name='([^']+)'", line)
                if permission_match:
                    permissions.append(permission_match.group(1))

        if package_name is None:
            raise ValueError("Failed to extract package name from aapt output")
        if version_code is None:
            raise ValueError("Failed to extract version code from aapt output")
        if sdk_version is None:
            raise ValueError("Failed to extract SDK version from aapt output")
        if target_sdk_version is None:
            raise ValueError("Failed to extract target SDK version from aapt output")

        return ApkAttributes(
            package_name=package_name,
            application_name=application_name,
            version_code=version_code,
            sdk_version=sdk_version,
            target_sdk_version=target_sdk_version,
            permissions=permissions,
            launchable_activity=launchable_activity,
        )


class ApkUnpacker(Unpacker[None]):
    """
    Decodes Android APK application packages into their component files and resources using apktool
    (see <https://ibotpeaches.github.io/Apktool/>). This tool decodes the AndroidManifest.xml back
    to readable XML, extracts resources (images, layouts, strings) in their original format,
    converts DEX bytecode to Smali assembly, and preserves the complete directory structure. Use
    when reverse engineering Android applications, analyzing app behavior, examining resource files,
    or preparing to modify and repackage an APK. The decoded files are much easier to read and
    modify than the compiled APK format.
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
        async with resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                cmd = [
                    "apktool",
                    "decode",
                    "--output",
                    temp_flush_dir,
                    "--force",
                    temp_path,
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
    Repackages decoded Android APK resources into a complete, signed APK file using apktool for
    compilation and uber-apk-signer for signing. The process recompiles resources, repackages DEX
    files, updates the manifest, and creates cryptographic signatures required for Android
    installation. Use after modifying Android app resources, Smali code, or manifest to create an
    installable APK.

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
        with tempfile.NamedTemporaryFile(suffix=apk_suffix, delete_on_close=False) as temp_apk:
            temp_apk.close()
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


MagicMimePattern.register(Apk, "application/vnd.android.package-archive")


class ApkIdentifier(Identifier):
    """
    Identifier for ApkArchive.

    Some Apks are recognized by the MagicMimePattern; others are tagged as JavaArchive or
    ZipArchive. This identifier inspects those files, and tags any with an androidmanifest.xml
    as an ApkArchive.
    """

    targets = (JavaArchive, ZipArchive)
    external_dependencies = (UNZIP_TOOL,)

    async def identify(self, resource: Resource, config=None) -> None:
        async with resource.temp_to_disk(suffix=".zip") as temp_path:
            unzip_cmd = [
                "unzip",
                "-l",
                temp_path,
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
