import pytest

from ofrak.model.component_model import ComponentExternalTool
from ofrak.ofrak_cli import (
    ListSubCommand,
    DepsSubCommand,
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
    subcommands = [ListSubCommand(), DepsSubCommand()]
    return OFRAKCommandLineInterface(ofrak_env, subcommands)


def _check_cli_output_matches(expected_output, capsys):
    output = capsys.readouterr().out
    assert output == expected_output


def test_list(ofrak_cli_parser, capsys):
    ofrak_cli_parser.parse_and_run(["list"])
    _check_cli_output_matches(
        "_MockOFRAKPackage\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-p", "-c"])
    _check_cli_output_matches(
        "_MockOFRAKPackage\n\t_MockComponentA\n\t_MockComponentB\n\t_MockComponentC\n_MockOFRAKPackage2\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-p"])
    _check_cli_output_matches(
        "_MockOFRAKPackage\n_MockOFRAKPackage2\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["list", "-c"])
    _check_cli_output_matches(
        "_MockComponentA\n_MockComponentB\n_MockComponentC\n",
        capsys,
    )


def test_deps(ofrak_cli_parser, capsys):
    ofrak_cli_parser.parse_and_run(["deps"])
    _check_cli_output_matches(
        "tool_a [_MockComponentA]\ntool_b [_MockComponentB]\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--package", "_MockOFRAKPackage2"])
    _check_cli_output_matches(
        "",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--component", "_MockComponentA"])
    _check_cli_output_matches(
        "tool_a [_MockComponentA]\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(
        ["deps", "--component", "_MockComponentA", "--component", "_MockComponentB"]
    )
    _check_cli_output_matches(
        "tool_a [_MockComponentA]\ntool_b [_MockComponentB]\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--dependency-packages", "apt"])
    _check_cli_output_matches(
        "tool_a_apt\n",
        capsys,
    )

    ofrak_cli_parser.parse_and_run(["deps", "--dependency-packages", "brew"])
    _check_cli_output_matches(
        "tool_a_brew\n",
        capsys,
    )


def test_ofrak_help():
    ofrak_env = OFRAKEnvironment()
    subcommands = [ListSubCommand(), DepsSubCommand()]
    ofrak_cli = OFRAKCommandLineInterface(ofrak_env, subcommands)
    try:
        ofrak_cli.parse_and_run(["--help"])
    except SystemExit as e:
        assert e.code == 0
