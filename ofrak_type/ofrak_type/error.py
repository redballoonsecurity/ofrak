from typing import Tuple, Optional, Dict


class NotFoundError(RuntimeError):
    pass


class AlreadyExistError(RuntimeError):
    pass


class InvalidStateError(RuntimeError):
    pass


class InvalidUsageError(RuntimeError):
    pass


class ComponentMissingDependencyError(RuntimeError):
    def __init__(
        self,
        dependency_name: str,
        install_packages: Dict[str, Optional[str]],
        install_hint: Optional[str] = None,
    ):
        errstring = (
            f"Missing an external tool needed for a component! {dependency_name} is missing."
        )
        if install_packages:
            install_str = "\n\t".join(
                f"{pkg_manager} installation: "
                + ("{pkg_manager} install {pkg}" if pkg else "unavailable")
                for pkg_manager, pkg in install_packages.items()
            )
            if not all(install_packages.values()):
                install_str += f"\n\tNot installable via all package managers, see: {install_hint}"
        else:
            install_str = f"Not installable via package manager. See the following: {install_hint}"

        errstring += "\n\t" + install_str

        super().__init__(errstring)


class ComponentSubprocessError(RuntimeError):
    def __init__(
        self,
        cmd: str,
        cmd_args: Tuple[str, ...],
        cmd_retcode: int,
        cmd_stdout: str,
        cmd_stderr: str,
    ):
        full_command = f"{cmd} {' '.join(cmd_args)}"
        errstring = (
            f"Command '{full_command}' returned non-zero exit status {cmd_retcode}.\n"
            f"Stderr: {cmd_stderr}.\n"
            f"Stdout: {cmd_stdout}."
        )
        super().__init__(errstring)
        self.cmd = cmd
        self.cmd_args = cmd_args
        self.cmd_retcode = cmd_retcode
        self.cmd_stdout = cmd_stdout
        self.cmd_stderr = cmd_stderr
