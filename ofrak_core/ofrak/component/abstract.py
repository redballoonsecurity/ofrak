import dataclasses
import inspect
import logging
from abc import ABC, abstractmethod
from subprocess import CalledProcessError
from typing import (
    Optional,
    Callable,
    Any,
    cast,
    Tuple,
)

from ofrak.component.interface import ComponentInterface
from ofrak.model.component_model import (
    CC,
    ComponentRunResult,
    ComponentConfig,
    ComponentExternalTool,
)
from ofrak.model.ofrak_context_interface import OFRAKContext2Interface
from ofrak.resource import Resource

LOGGER = logging.getLogger(__name__)


class AbstractComponent(ComponentInterface[CC], ABC):
    def __init__(
        self,
        ofrak_context: OFRAKContext2Interface,
    ):
        self._resource_factory = None
        self._default_config = self.get_default_config()

        self._context = ofrak_context
        self.__post_init__()

    def __post_init__(self):
        """
        Override for any state that a component needs to set up, without messing with the dependency
        injection that uses the constructor.

        :return:
        """

    @classmethod
    def get_id(cls) -> bytes:
        return cls.id if cls.id is not None else cls.__name__.encode()

    # By default, assume component has no external dependencies
    external_dependencies: Tuple[ComponentExternalTool, ...] = ()

    async def run(
        self,
        job_id: bytes,
        resource_id: bytes,
        config: CC,
    ) -> ComponentRunResult:
        """

        :param job_id:
        :param resource_id:
        :param config:
        :return: The IDs of all resources modified by this component
        """
        context = self._context.fork(
            job_id=job_id, component_id=self.get_id(), component_version=self.get_version()
        )
        (resource,) = await context.get_resources(resource_id)
        if config is None and self._default_config is not None:
            config = dataclasses.replace(self._default_config)

        try:
            await self._run(resource, context, config)
        except FileNotFoundError as e:
            # Check if the problem was that one of the dependencies is missing
            missing_file = e.filename
            for dep in self.external_dependencies:
                if dep.tool == missing_file:
                    raise ComponentMissingDependencyError(self, dep)
            raise
        except CalledProcessError as e:
            raise ComponentSubprocessError(e)

        await context.push()
        return context.get_cumulative_result()

    @abstractmethod
    async def _run(self, resource: Resource, context: OFRAKContext2Interface, config: CC):
        raise NotImplementedError()

    @staticmethod
    def _get_default_config_from_method(
        component_method: Callable[[Any, Resource, CC], Any]
    ) -> Optional[CC]:
        run_signature = inspect.signature(component_method)
        config_arg_type = run_signature.parameters["config"]
        default_arg: CC = config_arg_type.default

        if isinstance(default_arg, ComponentConfig):
            try:
                return cast(CC, default_arg)
            except TypeError as e:
                raise TypeError(
                    f"ComponentConfig subclass {type(default_arg)} is not a dataclass! This is "
                    f"required in order to copy the default config to ensure the default is "
                    f"non-mutable."
                ) from e
        elif default_arg is not None and default_arg is not config_arg_type.empty:
            raise TypeError(
                f"Default config {default_arg} must be either an instance of ComponentConfig, "
                f"None, or left empty!"
            )
        else:
            return None

    def get_version(self) -> int:
        return 1

    def _log_component_has_run_warning(self, resource: Resource):
        LOGGER.warning(
            f"{self.get_id().decode()} has already been run on resource {resource.get_id().hex()}"
        )


class ComponentMissingDependencyError(RuntimeError):
    def __init__(
        self,
        component: ComponentInterface,
        dependency: ComponentExternalTool,
    ):
        if dependency.apt_package:
            apt_install_str = f"\n\tapt installation: apt install {dependency.apt_package}"
        else:
            apt_install_str = ""
        if dependency.brew_package:
            brew_install_str = f"\n\tbrew installation: brew install {dependency.brew_package}"
        else:
            brew_install_str = ""

        super().__init__(
            f"Missing {dependency.tool} tool needed for {type(component).__name__}!"
            f"{apt_install_str}"
            f"{brew_install_str}"
            f"\n\tSee {dependency.tool_homepage} for more info and installation help."
            f"\n\tAlternatively, OFRAK can ignore this component (and any others with missing "
            f"dependencies) so that they will never be run: OFRAK(..., exclude_components_missing_dependencies=True)"
        )

        self.component = component
        self.dependency = dependency


class ComponentSubprocessError(RuntimeError):
    def __init__(self, error: CalledProcessError):
        errstring = (
            f"Command '{error.cmd}' returned non-zero exit status {error.returncode}.\n"
            f"Stderr: {error.stderr}.\n"
            f"Stdout: {error.stdout}."
        )
        super().__init__(errstring)
        self.cmd = error.cmd
        self.cmd_retcode = error.returncode
        self.cmd_stdout = error.stdout
        self.cmd_stderr = error.stderr
