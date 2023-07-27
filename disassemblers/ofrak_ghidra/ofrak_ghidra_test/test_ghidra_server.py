import psutil
import pytest
from typing import Optional

import ofrak_ghidra.server.__main__ as server_main


def _get_ghidra_server_process() -> Optional[psutil.Process]:
    for proc in psutil.process_iter():
        cmdline = proc.cmdline()
        if (
            len(cmdline) > 1
            and cmdline[0] == "/usr/lib/jvm/java-11-openjdk-amd64/bin/java"
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

    If the server is running, stop it, then restart it.
    If the server is not running ,start
    """
    if ghidra_is_running:
        server_main._stop_ghidra_server()
        assert not _is_ghidra_server_running(), "Could not stop Ghidra server"
    else:
        server_main._run_ghidra_server()
        assert _is_ghidra_server_running(), "Could not start Ghidra Server"
