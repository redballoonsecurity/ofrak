import psutil
import pytest

import ofrak_ghidra.server.__main__ as server_main


def _get_ghidra_server_process() -> psutil.Process:
    for proc in psutil.process_iter():
        cmdline = proc.cmdline()
        if (
            cmdline[0] == "/usr/lib/jvm/java-11-openjdk-amd64/bin/java"
            and cmdline[1] == "-Dwrapper.pidfile=/run/wrapper.ghidraSvr.pid"
        ):
            return proc
    raise ValueError("Could not find Ghidra server process")


def _is_ghidra_server_running() -> bool:
    try:
        pid = _get_ghidra_server_process()
        return True
    except ValueError:
        return False


@pytest.fixture
def ghidra_is_running() -> bool:
    """
    Get Ghidra server state before test, and restore state after test.
    """
    ghidra_is_running = _is_ghidra_server_running()

    yield ghidra_is_running

    if ghidra_is_running:
        server_main._run_ghidra_server("start")
    else:
        server_main._stop_ghidra_server("stop")


def test_start_stop_ghidra_server(ghidra_is_running: bool):
    """
    Test that the Ghidra server can be started and stopped using ofrak_ghidra.server.

    If the server is running, stop it, then restart it.
    If the server is not running ,start
    """
    if ghidra_is_running:
        server_main._stop_ghidra_server("stop")
        assert not _is_ghidra_server_running(), "Could not stop Ghidra server"
    else:
        server_main._run_ghidra_server("start")
        assert _is_ghidra_server_running(), "Could not start Ghidra Server"
