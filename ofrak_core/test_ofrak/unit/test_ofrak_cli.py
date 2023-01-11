from typing import Iterable

import pytest

from ofrak.ofrak_cli import (
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
def ofrak_cli_parser():
    ofrak_env = MockOFRAKEnvironment()
    return OFRAKCommandLineInterface(ofrak_env)  # type: ignore


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


def test_ofrak_help():
    ofrak_env = OFRAKEnvironment()
    ofrak_cli = OFRAKCommandLineInterface(ofrak_env)
    try:
        ofrak_cli.parse_and_run(["--help"])
    except SystemExit as e:
        assert e.code == 0


def test_install_checks():
    ofrak_cli = OFRAKCommandLineInterface()
    ofrak_cli.parse_and_run(["deps", "--package", "ofrak"])
