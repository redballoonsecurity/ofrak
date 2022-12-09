from typing import Iterable

import pytest

from ofrak.model.component_model import ComponentExternalTool
from ofrak.ofrak_cli import (
    OFRAKCommandLineInterface,
    OFRAKEnvironment,
)
from pytest_ofrak.mock_component_types import MockUnpacker


class _MockOFRAKPackage:
    # Just needs to have a __name__ attr
    pass


class _MockOFRAKPackage2:
    # Just needs to have a __name__ attr
    pass


class _MockComponentA(MockUnpacker):
    external_dependencies = (ComponentExternalTool("tool_a", "tool_a.com", "--help", "tool_a_apt"),)


class _MockComponentB(MockUnpacker):
    external_dependencies = (
        ComponentExternalTool("tool_b", "tool_b.com", "--help", None, "tool_a_brew"),
    )


class _MockComponentC(MockUnpacker):
    pass


class MockOFRAKEnvironment:
    def __init__(self):
        self.packages = {
            "_MockOFRAKPackage": _MockOFRAKPackage,
            "_MockOFRAKPackage2": _MockOFRAKPackage2,
        }
        self.components = {
            "_MockComponentA": _MockComponentA,
            "_MockComponentB": _MockComponentB,
            "_MockComponentC": _MockComponentC,
        }
        self.components_by_package = {
            _MockOFRAKPackage: [_MockComponentA, _MockComponentB, _MockComponentC],
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
        "_MockOFRAKPackage\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-p", "-c"])
    _check_cli_output_matches_one_of(
        (
            "_MockOFRAKPackage\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage\n\t_MockComponentB\n\t_MockComponentA\n\t_MockComponentC\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage\n\t_MockComponentB\n\t_MockComponentC\n\t_MockComponentA\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage\n\t_MockComponentC\n\t_MockComponentA\n\t_MockComponentB\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage\n\t_MockComponentC\n\t_MockComponentB\n\t_MockComponentA\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage2\n_MockOFRAKPackage\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n",
            "_MockOFRAKPackage2\n_MockOFRAKPackage\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n",
            "_MockOFRAKPackage2\n_MockOFRAKPackage\n\t_MockComponentB\n\t_MockComponentA\n\t_MockComponentC\n",
            "_MockOFRAKPackage2\n_MockOFRAKPackage\n\t_MockComponentB\n\t_MockComponentC\n\t_MockComponentA\n",
            "_MockOFRAKPackage2\n_MockOFRAKPackage\n\t_MockComponentC\n\t_MockComponentA\n\t_MockComponentB\n",
            "_MockOFRAKPackage2\n_MockOFRAKPackage\n\t_MockComponentC\n\t_MockComponentB\n\t_MockComponentA\n",
        ),
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-p"])
    _check_cli_output_matches_one_of(
        (
            "_MockOFRAKPackage\n_MockOFRAKPackage2\n",
            "_MockOFRAKPackage2\n_MockOFRAKPackage\n",
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
