import os
import subprocess

subprocess.run(["pip", "uninstall", "xattr", "-y"])

import pytest


@pytest.mark.serial
async def test_filesystem_without_xattr():
    cwd = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    result = subprocess.run(["pytest", "./test_filesystem_component.py"])
    assert result.returncode == 0
    os.chdir(cwd)


subprocess.run(["pip", "install", "xattr"])
