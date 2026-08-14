import logging
from typing import Any, Callable, Dict, Optional, Tuple, Union

import pyghidra

from ofrak_pyghidra.standalone.pyghidra_analysis import extract_analysis

LOGGER = logging.getLogger("ofrak_pyghidra")


def run_script(
    program_file: str,
    script: Union[str, Callable[..., Any]],
    language: Optional[str] = None,
    script_globals: Optional[Dict[str, Any]] = None,
    refresh_analysis: bool = True,
    decompiled: bool = False,
    base_address: Optional[int] = None,
) -> Tuple[Any, Optional[Dict[str, Any]]]:
    """
    Run an arbitrary PyGhidra script against a program and save the resulting Ghidra state.

    The program is opened with `pyghidra.open_program`, which reuses the Ghidra project saved
    next to `program_file` (`<program_file>_ghidra`) if one exists. State saved by previous
    sessions (renames, applied types, forced disassembly, added memory blocks, etc.) is loaded
    before the script runs, and any changes the script makes are saved back to the project when
    the session exits. Auto-analysis is only run the first time a program is opened, so a script
    never clobbers previously saved state.

    The script runs inside a single Ghidra transaction, which is committed if the script returns
    normally and rolled back if it raises.

    :param program_file: path to the binary to open; the Ghidra project is stored beside it
    :param script: the script to run. Either a callable, invoked as `script(flat_api)`, or a
        string of Python source, executed with `flat_api`, `currentProgram`, and `monitor` in
        scope. A source script can define a variable named `result` to return a value.
    :param language: Ghidra language ID (e.g. `x86:LE:64:default`); only used when the program
        is imported for the first time
    :param script_globals: extra names to inject into the namespace of a source-string script
    :param refresh_analysis: if True, re-extract the analysis cache after the script runs so
        OFRAK components see the post-script Ghidra state
    :param decompiled: if True, include decompilation of every function when refreshing the
        analysis cache
    :param base_address: base address the program was previously rebased to, recorded in the
        refreshed cache metadata

    :return: a tuple of the script result and the refreshed analysis cache (None if
        `refresh_analysis` is False). For a callable the result is its return value; for a
        source-string script it is the value of the variable named `result`, if defined.
    """
    with pyghidra.open_program(program_file, language=language) as flat_api:
        program = flat_api.getCurrentProgram()
        transaction = program.startTransaction("OFRAK PyGhidra script")
        commit = False
        try:
            if callable(script):
                result = script(flat_api)
            else:
                script_namespace: Dict[str, Any] = {
                    "flat_api": flat_api,
                    "currentProgram": program,
                    "monitor": flat_api.getMonitor(),
                }
                if script_globals is not None:
                    script_namespace.update(script_globals)
                exec(compile(script, "<ofrak_pyghidra_script>", "exec"), script_namespace)
                result = script_namespace.get("result")
            commit = True
        finally:
            program.endTransaction(transaction, commit)

        analysis = None
        if refresh_analysis:
            LOGGER.info("Refreshing analysis cache after script run")
            analysis = extract_analysis(flat_api, program_file, decompiled, base_address)
    return result, analysis
