"""
Test the Ghidra configuration functionality.
"""
from dataclasses import dataclass

import pytest

from ofrak_ghidra.config.__main__ import _dump_config, _import_config, _restore_config
from ofrak_ghidra.config.ofrak_ghidra_config import load_ghidra_config, save_ghidra_config

DEFAULT_CONFIG = """ghidra_install:
  log_file: ~/.ghidra/.ghidra_11.3.2_PUBLIC/application.log
  path: /opt/rbs/ghidra_11.3.2_PUBLIC
  version: 11.3.2
server:
  analysis:
    host: localhost
    port: 13300
  pass: changeme
  repository:
    host: localhost
    port: 13100
  use_sudo: false
  user: root
"""

MODIFIED_CONFIG = """ghidra_install:
  log_file: /tmp/test_ghidra.log
  path: /tmp/test_ghidra
  version: 11.3.2
server:
  analysis:
    host: TEST_ANALYSIS_HOST
    port: 1337
  pass: hunter2
  repository:
    host: TEST_REPO_HOST
    port: 666
  use_sudo: true
  user: testuser
"""


@dataclass
class Args:
    config_path: str


@pytest.fixture(autouse=True)
def isolate_config():
    """
    Save the user's config before each test, reset to defaults for the test,
    and restore the original config afterward so user settings are not corrupted.
    """
    original = load_ghidra_config()
    _restore_config(None)
    yield
    save_ghidra_config(original)


def test_dump_config(capsys):
    """
    Test that ofrak_ghira.config dump returns expected output.

    This test verifies that:
    - The dump command outputs the default configuration
    """
    _validate_config(capsys, DEFAULT_CONFIG)


def test_import_config(capsys, tmp_path):
    """
    Test that importing a config changes the default config.

    This test verifies that:
    - The default configuration can be overridden with a custom one
    """
    # Validate default config is set
    _validate_config(capsys, DEFAULT_CONFIG)

    # Change the default config
    path = tmp_path / "config.yml"
    with open(path, "w") as f:
        f.write(MODIFIED_CONFIG)
    _import_config(Args(path))

    # Assert config is changed
    _validate_config(capsys, MODIFIED_CONFIG)


def test_restore_config(capsys, tmp_path):
    """
    Test that "ofrak_ghidra.config restore" restores the default config file.

    This test verifies that:
    - A modified configuration can be restored to the original default
    """
    # Change the default config
    path = tmp_path / "config.yml"
    with open(path, "w") as f:
        f.write(MODIFIED_CONFIG)
    _import_config(Args(path))

    # Assert config is modified config
    _validate_config(capsys, MODIFIED_CONFIG)

    # Restore config and validate that it is restored
    _restore_config(None)
    _validate_config(capsys, DEFAULT_CONFIG)


def _validate_config(capsys, expected_config: str):
    _dump_config(None)
    captured = capsys.readouterr()
    assert captured.out == expected_config + "\n"


def test_ofrak_ghidra_config_help():
    """
    Assert that OFRAKGhidraConfig.config_help returns a help string.

    This test verifies that:
    - The configuration class provides a help method
    """
    config = load_ghidra_config()
    assert isinstance(config.config_help(), str)
