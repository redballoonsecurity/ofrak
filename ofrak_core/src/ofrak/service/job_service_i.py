from abc import ABCMeta, abstractmethod
from typing import Optional, Tuple

from ofrak.model.component_model import ComponentRunResult
from ofrak.model.job_model import (
    JobModel,
    JobRunContext,
)
from ofrak.model.job_request_model import (
    JobAnalyzerRequest,
    JobComponentRequest,
    JobMultiComponentRequest,
)
from ofrak.service.abstract_ofrak_service import AbstractOfrakService
from ofrak.service.component_locator_i import ComponentFilter


class JobServiceInterface(AbstractOfrakService, metaclass=ABCMeta):
    """
    Job service interface.
    """

    @abstractmethod
    async def create_job(self, id: bytes, name: str) -> JobModel:
        pass

    @abstractmethod
    async def run_component(
        self,
        request: JobComponentRequest,
        job_context: Optional[JobRunContext] = None,
    ) -> ComponentRunResult:
        """
        Run a single component for a job.

        :param request:
        :param job_context: Context of the job to run the component in.

        :return: A data structure describing the component run and resources
        modified/created/deleted.
        """

    @abstractmethod
    async def run_analyzer_by_attribute(
        self,
        request: JobAnalyzerRequest,
        job_context: Optional[JobRunContext] = None,
    ) -> ComponentRunResult:
        """
        Choose one or more Analyzer components to analyze the requested attributes on the given
        resource.

        :param request: Data structure containing the ID of the job to run the components in,
        the ID of the resource to run components on, which attributes the Analyzers should
        output, and the tags of the target resource.
        :param job_context: Context of the job to run the component in.

        :return: A data structure describing the component(s) run and resources
        modified/created/deleted.

        :raises NotFoundError: If no Analyzers can be found targeting the specified tags and
        outputting the specified attributes.
        """

    @abstractmethod
    async def run_components(
        self,
        request: JobMultiComponentRequest,
    ) -> ComponentRunResult:
        """
        Automatically select one or more components to run on a resource. The components must
        match the provided component filters and target at least one of the tags of the resource.

        :param request: Data structure containing the ID of the job to run the components in,
        the ID of the resource to run components on, and filters for the components to
        run.

        :return: A data structure describing the components run and resources
        modified/created/deleted.

        :raises ComponentAutoRunFailure: if one of the automatically chosen components raises an
        error while running.
        :raises NoMatchingComponentException: if no components match the filters for the resource.
        """

    @abstractmethod
    async def run_components_recursively(
        self,
        request: JobMultiComponentRequest,
    ) -> ComponentRunResult:
        """
        Start from a resource and run components on it and then on any resources which have tags
        added as a result of that initial run, then run components on any resources with new tags
        from those subsequent runs, until an iteration of component runs results in no new tags
        being added. The component(s) run on each resource are chosen according to the provided
        filters and which tags were added to that resource in the previous iteration. That is,
        the filters are applied to the set of resource which target those new tags.

        :param request: Data structure containing the ID of the job to run the components in,
        the ID of the resource to start running recursively from, and filters for the components to
        run.

        :return: A data structure describing the components run and resources
        modified/created/deleted.

        :raises ComponentAutoRunFailure: if one of the automatically chosen components raises an
        error while running.
        """

    @abstractmethod
    async def pack_recursively(
        self,
        job_id: bytes,
        resource_id: bytes,
    ) -> ComponentRunResult:
        """
        Call Packer components on the deepest descendants of a resource (the root of this search),
        then Packers on the next level up, etc. until the search root resource.

        :param job_id: Job to run the component in.
        :param resource_id: ID of the search root resource.

        :return: A data structure describing the components run and resources
        modified/created/deleted.
        """


class ComponentAutoRunFailure(Exception):
    def __init__(
        self,
        target_resource_id: bytes,
        component_filters: Tuple[ComponentFilter, ...],
        failing_component_id: bytes,
    ):
        super().__init__(
            f"Component {failing_component_id.decode()} failed when running on "
            f"{target_resource_id.hex()}. Component was chosen because it matched filters "
            f"{component_filters}"
        )
        self.target_resource_id = target_resource_id
        self.component_filters = component_filters
        self.failing_component_id = failing_component_id
