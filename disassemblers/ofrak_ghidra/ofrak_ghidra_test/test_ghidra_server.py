import ofrak_ghidra.server.__main__ as server_main

from typing import Optional

import psutil


def _get_ghidra_server_process() -> Optional[psutil.Process]:
    ghidra_pid = None
    for proc in psutil.process_iter():
        cmdline = proc.cmdline()
        if (
            cmdline[0] == "/usr/lib/jvm/java-11-openjdk-amd64/bin/java"
            and cmdline[1] == "-Dwrapper.pidfile=/run/wrapper.ghidraSvr.pid"
        ):
            ghidra_pid = proc

    return ghidra_pid


def _is_ghidra_server_running() -> bool:
    pid = _get_ghidra_server_process()

    if isinstance(pid, psutil.Process):
        return True
    else:
        return False


def test_start_ofrak_ghidra_server():
    if _is_ghidra_server_running():
        process = _get_ghidra_server_process()
        if process is not None:
            process.kill()

    server_main._run_ghidra_server("start")

    assert _is_ghidra_server_running(), "Tried to start server, but could not find process"


def test_stop_ofrak_ghidra_server():
    if not _is_ghidra_server_running():
        server_main._run_ghidra_server("start")

    assert _is_ghidra_server_running(), "Could not start Ghidra server"

    server_main._stop_ghidra_server("stop")

    assert not _is_ghidra_server_running(), "Could not stop Ghidra server"
