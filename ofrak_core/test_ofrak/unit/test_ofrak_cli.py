import hashlib
import os
from typing import Iterable, Dict, Tuple

import pytest
from dataclasses import fields

from ofrak.cli.command.gui import GUICommand
from ofrak.ofrak_context import OFRAKContext

import test_ofrak.components
from ofrak.cli.command.identify import IdentifyCommand
from ofrak.cli.command.unpack import UnpackCommand

from ofrak.cli.command.deps import DepsCommand
from ofrak.cli.command.list import ListCommand
from ofrak.cli.ofrak_cli import (
    OFRAKCommandLineInterface,
    OFRAKEnvironment,
)
from pytest_ofrak import mock_library3
from pytest_ofrak.mock_library3 import _MockComponentA, _MockComponentB, _MockComponentC


class _MockOFRAKPackage2:
    # Just needs to have a __name__ attr
    pass


class MockOFRAKEnvironment:
    def __init__(self):
        self.packages = {
            "pytest_ofrak.mock_library3": mock_library3,
            "_MockOFRAKPackage2": _MockOFRAKPackage2,
        }
        self.components = {
            "_MockComponentA": mock_library3._MockComponentA,
            "_MockComponentB": mock_library3._MockComponentB,
            "_MockComponentC": mock_library3._MockComponentC,
        }
        self.components_by_package = {
            mock_library3: [_MockComponentA, _MockComponentB, _MockComponentC],
            _MockOFRAKPackage2: [],
        }
        self.dependencies_by_component = {
            c: c.external_dependencies for c in [_MockComponentA, _MockComponentB, _MockComponentC]
        }


@pytest.fixture
def cli_commands():
    return [ListCommand(), DepsCommand(), IdentifyCommand(), UnpackCommand(), GUICommand()]


@pytest.fixture
def ofrak_cli_parser(cli_commands):
    ofrak_env = MockOFRAKEnvironment()
    return OFRAKCommandLineInterface(cli_commands, ofrak_env)  # type: ignore


def _check_cli_output_matches(expected_output: str, capsys):
    output = capsys.readouterr().out
    assert output == expected_output


def _check_cli_output_matches_one_of(expected_outputs: Iterable[str], capsys):
    output = capsys.readouterr().out
    assert any(output == expected_output for expected_output in expected_outputs)


def test_list(ofrak_cli_parser, capsys):
    ofrak_cli_parser.parse_and_run(["list"])
    _check_cli_output_matches(
        "pytest_ofrak.mock_library3\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-p", "-c"])
    _check_cli_output_matches_one_of(
        (
            "pytest_ofrak.mock_library3\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
            "pytest_ofrak.mock_library3\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
            "pytest_ofrak.mock_library3\n\t_MockComponentB\n\t_MockComponentA\n\t_MockComponentC\n_MockOFRAKPackage2\n",
            "pytest_ofrak.mock_library3\n\t_MockComponentB\n\t_MockComponentC\n\t_MockComponentA\n_MockOFRAKPackage2\n",
            "pytest_ofrak.mock_library3\n\t_MockComponentC\n\t_MockComponentA\n\t_MockComponentB\n_MockOFRAKPackage2\n",
            "pytest_ofrak.mock_library3\n\t_MockComponentC\n\t_MockComponentB\n\t_MockComponentA\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage2\npytest_ofrak.mock_library3\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n",
            "_MockOFRAKPackage2\npytest_ofrak.mock_library3\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n",
            "_MockOFRAKPackage2\npytest_ofrak.mock_library3\n\t_MockComponentB\n\t_MockComponentA\n\t_MockComponentC\n",
            "_MockOFRAKPackage2\npytest_ofrak.mock_library3\n\t_MockComponentB\n\t_MockComponentC\n\t_MockComponentA\n",
            "_MockOFRAKPackage2\npytest_ofrak.mock_library3\n\t_MockComponentC\n\t_MockComponentA\n\t_MockComponentB\n",
            "_MockOFRAKPackage2\npytest_ofrak.mock_library3\n\t_MockComponentC\n\t_MockComponentB\n\t_MockComponentA\n",
        ),
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-p"])
    _check_cli_output_matches_one_of(
        (
            "pytest_ofrak.mock_library3\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage2\npytest_ofrak.mock_library3\n",
        ),
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-c"])
    _check_cli_output_matches_one_of(
        (
            "_MockComponentA\n_MockComponentB\n_MockComponentC\n",
            "_MockComponentB\n_MockComponentA\n_MockComponentC\n",
            "_MockComponentB\n_MockComponentC\n_MockComponentA\n",
            "_MockComponentC\n_MockComponentA\n_MockComponentB\n",
            "_MockComponentC\n_MockComponentB\n_MockComponentA\n",
        ),
        capsys,
    )


def test_deps(ofrak_cli_parser, capsys):
    ofrak_cli_parser.parse_and_run(["deps", "--no-check"])
    _check_cli_output_matches_one_of(
        (
            "tool_a\n\ttool_a.com\n\t[_MockComponentA]\ntool_b\n\ttool_b.com\n\t[_MockComponentB]\n",
            "tool_b\n\ttool_b.com\n\t[_MockComponentB]\ntool_a\n\ttool_a.com\n\t[_MockComponentA]\n",
        ),
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--package", "_MockOFRAKPackage2", "--no-check"])
    _check_cli_output_matches(
        "",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--component", "_MockComponentA", "--no-check"])
    _check_cli_output_matches(
        "tool_a\n\ttool_a.com\n\t[_MockComponentA]\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(
        ["deps", "--component", "_MockComponentA", "--component", "_MockComponentB", "--no-check"]
    )
    _check_cli_output_matches_one_of(
        (
            "tool_a\n\ttool_a.com\n\t[_MockComponentA]\ntool_b\n\ttool_b.com\n\t[_MockComponentB]\n",
            "tool_b\n\ttool_b.com\n\t[_MockComponentB]\ntool_a\n\ttool_a.com\n\t[_MockComponentA]\n",
        ),
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--packages-for", "apt"])
    _check_cli_output_matches(
        "tool_a_apt\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--packages-for", "brew"])
    _check_cli_output_matches(
        "tool_a_brew\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--no-packages-for", "apt", "--no-check"])
    _check_cli_output_matches(
        "tool_b\n\ttool_b.com\n\t[_MockComponentB]\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--no-packages-for", "brew", "--no-check"])
    _check_cli_output_matches(
        "tool_a\n\ttool_a.com\n\t[_MockComponentA]\n",
        capsys,
    )


TEST_FILES = [
    "simple_arm_gcc.o.elf",
    "jumpnbump.exe",
    "testtar.tar",
]


@pytest.fixture
async def all_expected_analysis(ofrak_context: OFRAKContext):
    all_expected_analysis = dict()
    for filename in TEST_FILES:
        file_path = os.path.join(
            os.path.dirname(test_ofrak.components.__file__), "assets", filename
        )
        test_resource = await ofrak_context.create_root_resource_from_file(file_path)
        await test_resource.identify()
        expected_tags = test_resource.get_most_specific_tags()
        expected_attributes = test_resource.get_model().attributes.values()
        all_expected_analysis[filename] = expected_tags, expected_attributes
    await ofrak_context.shutdown_context()
    return all_expected_analysis


@pytest.mark.parametrize("filename", TEST_FILES)
def test_identify(ofrak_cli_parser, capsys, filename, all_expected_analysis: Tuple[Dict, Dict]):
    expected_tags, expected_attributes = all_expected_analysis[filename]
    assert len(expected_tags) > 0
    assert len(expected_attributes) > 0
    file_path = os.path.join(os.path.dirname(test_ofrak.components.__file__), "assets", filename)
    ofrak_cli_parser.parse_and_run(["identify", file_path])

    captured = capsys.readouterr()
    for tag in expected_tags:
        assert str(tag.__name__) in captured.out

    for attribute in expected_attributes:
        for field in fields(attribute):
            field_content = str(getattr(attribute, field.name))
            assert (
                field_content in captured.out
            ), f"Expected {field_content}, not found in \n\t{captured.out}"


@pytest.fixture
async def all_expected_hashes(ofrak_context: OFRAKContext):
    all_expected_hashes = dict()
    for filename in TEST_FILES:
        expected_hashes = set()
        file_path = os.path.join(
            os.path.dirname(test_ofrak.components.__file__), "assets", filename
        )
        res = await ofrak_context.create_root_resource_from_file(file_path)
        await res.unpack()
        for child in await res.get_descendants():
            if child.get_data_id() is not None:
                data = await child.get_data()
                if len(data) > 0:
                    expected_hashes.add(hashlib.sha256(data).hexdigest())
        all_expected_hashes[filename] = expected_hashes
    await ofrak_context.shutdown_context()
    return all_expected_hashes


@pytest.mark.parametrize("filename", TEST_FILES)
def test_unpack(ofrak_cli_parser, capsys, filename, tmpdir, ofrak_context, all_expected_hashes):
    file_path = os.path.join(os.path.dirname(test_ofrak.components.__file__), "assets", filename)
    ofrak_cli_parser.parse_and_run(["unpack", "-o", str(tmpdir), file_path])

    unpacked_hashes = set()
    for dirpath, dirnames, filenames in os.walk(tmpdir):
        if dirpath == tmpdir:
            continue
        assert dirpath.endswith(".ofrak_children")
        for unpacked_file in filenames:
            path = os.path.join(dirpath, unpacked_file)
            with open(path, "rb") as file:
                unpacked_hashes.add(hashlib.sha256(file.read()).hexdigest())
    expected_hashes = all_expected_hashes[filename]

    assert unpacked_hashes == expected_hashes

    info_dump_file = os.path.join(tmpdir, "__ofrak_info__")
    with open(info_dump_file) as f:
        info_dump = f.read()

    assert len(info_dump) > 1
    # Some unicode characters which will be malformed if the re-encoding is messed up
    assert any(["┌" in info_dump, "┬" in info_dump, "─" in info_dump])


def test_ofrak_help(cli_commands):
    ofrak_env = OFRAKEnvironment()
    ofrak_cli = OFRAKCommandLineInterface(cli_commands, ofrak_env)
    try:
        ofrak_cli.parse_and_run(["--help"])
    except SystemExit as e:
        assert e.code == 0


def test_install_checks(cli_commands):
    ofrak_cli = OFRAKCommandLineInterface(cli_commands)
    ofrak_cli.parse_and_run(["deps", "--package", "ofrak"])
