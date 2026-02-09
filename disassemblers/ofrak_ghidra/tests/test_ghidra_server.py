"""
Test the Ghidra server management functionality.
"""
import os
import re
import time

import psutil
import pytest
from typing import Optional

import ofrak_ghidra.server.__main__ as server_main
from ofrak_ghidra.constants import conf

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 and not conf.use_sudo,
    reason="Ghidra server management requires root or use_sudo config",
)


def _get_ghidra_server_process() -> Optional[psutil.Process]:
    for proc in psutil.process_iter():
        try:
            cmdline = proc.cmdline()
        except (psutil.ZombieProcess, psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if (
            len(cmdline) > 1
            # Match any non-slash character
            and re.match("/usr/lib/jvm/[^/]*/bin/java", cmdline[0])
            and cmdline[1] == "-Dwrapper.pidfile=/run/wrapper.ghidraSvr.pid"
        ):
            return proc
    return None


def _is_ghidra_server_running() -> bool:
    proc = _get_ghidra_server_process()
    return proc is not None


@pytest.fixture
def ghidra_is_running() -> bool:
    """
    Get Ghidra server state before test, and restore state after test.
    """
    ghidra_is_running = _is_ghidra_server_running()

    yield ghidra_is_running

    if ghidra_is_running:
        server_main._run_ghidra_server()
    else:
        server_main._stop_ghidra_server()


def test_start_stop_ghidra_server(ghidra_is_running: bool):
    """
    Test that the Ghidra server can be started and stopped using ofrak_ghidra.server.

    This test verifies that:
    - The Ghidra server can be started if it is not running
    - The Ghidra server can be stopped if it is running
    """
    if ghidra_is_running:
        server_main._stop_ghidra_server()
        time.sleep(3)
        assert not _is_ghidra_server_running(), "Could not stop Ghidra server"
    else:
        server_main._run_ghidra_server()
        assert _is_ghidra_server_running(), "Could not start Ghidra Server"
