import asyncio
import dataclasses
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Set, Type, Dict, List, TypeVar, Optional, ClassVar, Tuple, cast

from ofrak.model.data_model import DataPatch
from ofrak.model.resource_model import ResourceAttributes
from ofrak_type.error import ComponentSubprocessError, ComponentMissingDependencyError
from ofrak_type.range import Range

CLIENT_COMPONENT_ID = b"__client_context__"
CLIENT_COMPONENT_VERSION = -1


@dataclass
class ComponentConfig:
    """
    Base class for all components' configs. All subclasses should also be dataclasses.
    """


@dataclass
class ComponentExternalTool:
    """
    An external tool or utility (like `zip` or `squashfs`) a component depends on. Includes some
    basic information on installation, either via package manager or bespoke process.

    There is a set of required package managers: ``ComponentExternalTool.REQUIRED_PKG_MANAGERS``. By
    default, OFRAK assumes that a tool can be installed with `<pkg_manager> install <tool>`. If this
    is not the case but the tool can still be installed via package manager (for example, the
    package containing the tool does not have the same name as the tool itself), custom packages for
    each manager can be provided. If the tool cannot be installed via one or more package manager
    at all, the package for that manager should be provided as None, and the `install_hint` must be
    provided so that a user has some guidance on how to install the tool.

    :ivar tool: Name of the command-line tool that will be run
    :ivar install_packages: Dictionary of package names to install `tool` for different package
    managers, including all of ``ComponentExternalTool.REQUIRED_PKG_MANAGERS``; by default, it is
    assumed that a tool can be installed via a package of the same name, so this argument is only
    necessary if that is NOT the case for one or more package managers.
    :ivar install_hints: String to provide guidance for a user on how to install a tool; only
    required if it is not possible to install via the supported package managers.
    :ivar install_check_arg: Argument to pass to the tool to check if it can be found and run on
    the host; defaults to `--help` so that by default, `tool`'s install is checked with:
        `<tool> --help`
    """

    tool: str
    install_packages: Dict[str, Optional[str]] = dataclasses.field(default_factory=dict)
    install_hints: Optional[str] = None  # e.g. version
    install_check_arg: str = "--help"

    REQUIRED_PKG_MANAGERS: ClassVar[Tuple[str, ...]] = ("brew", "apt")

    def __post_init__(self):
        if len(self.install_packages) == 0:
            self.install_packages = {pkg_man: self.tool for pkg_man in self.REQUIRED_PKG_MANAGERS}
        elif any(pkg_man not in self.install_packages for pkg_man in self.REQUIRED_PKG_MANAGERS):
            raise ValueError(
                f"Must include [{', '.join(self.REQUIRED_PKG_MANAGERS)}] packages for {self.tool} "
                f"(can be None for one or more of these if the tool cannot be installed via "
                f"call these package managers, as long as an install_hint is provided as well)"
            )
        elif None in self.install_packages.values() and self.install_hints is None:
            raise ValueError(
                f"If {self.tool} is not installable via one of "
                f"[{', '.join(self.REQUIRED_PKG_MANAGERS)}], an `install_hint` must be provided "
                f"for users."
            )

    async def run_tool(
        self, *args: str, input: Optional[bytes] = None, **create_subprocess_exec_kwargs
    ) -> bytes:
        """
        Run an external CLI tool this component depends on, as a subprocess.

        :param args: arguments to give the tool
        :param input: some input to provide via stdin, if the tool requires it
        :param create_subprocess_exec_kwargs: keyword args to pass through to
        create_subprocess_exec, in order to make use of lower-level functionality subprocess
        functionality (e.g. cwd=temp_dir to set the working directory of the tool invocation).

        :return: standard output if the subprocess completes successfully.

        :raises ComponentMissingDependencyError: If the OS indicates it cannot find the tool.
        :raises ComponentSubprocessError: If the subprocess fails (any return other than 0).
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tool,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input is not None else None,
                **create_subprocess_exec_kwargs,
            )
        except FileNotFoundError:
            raise ComponentMissingDependencyError(
                self.tool, self.install_packages, self.install_hints
            )

        proc_stdout, proc_stderr = await proc.communicate(input)
        if proc.returncode == 0:
            return proc_stdout
        else:
            try:
                decoded_proc_stdout = proc_stdout.decode("ascii")
            except UnicodeDecodeError:
                decoded_proc_stdout = (
                    "<OFRAK error handler could decode process stdout to "
                    "ASCII; stdout may be binary data>"
                )
            raise ComponentSubprocessError(
                self.tool,
                args,
                cast(int, proc.returncode),
                decoded_proc_stdout,
                proc_stderr.decode("ascii"),
            )

    async def is_tool_installed(self) -> bool:
        """
        Check if a tool is installed by running it with the `install_check_arg`. This defaults to
        `--help`, so by default, this method runs `<tool> --help`.

        :return: True if the `tool` command returned zero, False if `tool` could not be found or
        returned non-zero exit code.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tool,
                self.install_check_arg,
            )
        except FileNotFoundError:
            return False

        retcode = await proc.wait()
        if retcode == 0:
            return True
        else:
            return False


CC = TypeVar("CC", bound=Optional[ComponentConfig])


@dataclass
class ComponentRunResult:
    """
    Dataclass created after one or more components complete, holding high-level information about
    what resources were affected by a component or components
    """

    components_run: Set[bytes] = field(default_factory=set)
    resources_modified: Set[bytes] = field(default_factory=set)
    resources_deleted: Set[bytes] = field(default_factory=set)
    resources_created: Set[bytes] = field(default_factory=set)

    def update(self, other_results: "ComponentRunResult"):
        self.components_run.update(other_results.components_run)
        self.resources_modified.update(other_results.resources_modified)
        self.resources_created.update(other_results.resources_created)
        self.resources_deleted.update(other_results.resources_deleted)


@dataclass
class ComponentResourceAccessTracker:
    data_accessed: Set[Range] = field(default_factory=set)
    attributes_accessed: Set[Type[ResourceAttributes]] = field(default_factory=set)


@dataclass
class ComponentResourceModificationTracker:
    data_patches: List[DataPatch] = field(default_factory=list)


@dataclass
class ComponentContext:
    component_id: bytes
    component_version: int
    access_trackers: Dict[bytes, ComponentResourceAccessTracker] = field(
        default_factory=lambda: defaultdict(ComponentResourceAccessTracker)
    )
    modification_trackers: Dict[bytes, ComponentResourceModificationTracker] = field(
        default_factory=lambda: defaultdict(ComponentResourceModificationTracker)
    )
    resources_created: Set[bytes] = field(default_factory=set)
    resources_deleted: Set[bytes] = field(default_factory=set)

    def mark_resource_modified(self, r_id: bytes):
        # Creates a new tracker if none exists, and leaves tracker untouched if it already exists
        _ = self.modification_trackers[r_id]

    def get_modified_resource_ids(self, include_deleted=False) -> Set[bytes]:
        modified_resource_ids = set(self.modification_trackers.keys())
        if not include_deleted:
            modified_resource_ids = modified_resource_ids.difference(self.resources_deleted)
        return modified_resource_ids


class ClientComponentContext(ComponentContext):
    def __init__(self):
        super().__init__(CLIENT_COMPONENT_ID, CLIENT_COMPONENT_VERSION)
