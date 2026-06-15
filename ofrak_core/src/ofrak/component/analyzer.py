import logging
from abc import ABC, abstractmethod
from typing import Type, Tuple, Generic, TypeVar, Union, cast, Iterable, Optional

from ofrak.resource import Resource

from ofrak.component.abstract import AbstractComponent
from ofrak.model.component_model import CC
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.viewable_tag_model import ViewableResourceTag
from ofrak.resource_view import ResourceView

LOGGER = logging.getLogger(__name__)

AnalyzerReturnType = TypeVar(
    "AnalyzerReturnType",
    bound=Union[
        Tuple[ResourceAttributes, ...],
        ResourceAttributes,
        ResourceView,
    ],
)


class AnalyzerError(RuntimeError):
    """Base exception raised by analyzers."""


class Analyzer(AbstractComponent, Generic[CC, AnalyzerReturnType], ABC):
    """
    Analyzers are discrete components that gather and analyze specific information from the target
    [Resource][ofrak.resource.Resource]. Analyzers return custom processed
    data results.
    """

    @property
    @abstractmethod
    def outputs(
        self,
    ) -> Union[Tuple[Type[ResourceAttributes]], Tuple[ViewableResourceTag]]:
        raise NotImplementedError()

    @abstractmethod
    async def analyze(self, resource: Resource, config: CC) -> AnalyzerReturnType:
        """
        Analyze a resource for to extract specific
        [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes].

        Users should not call this method directly; rather, they should run
        [Resource.run][ofrak.resource.Resource.run] or
        [Resource.analyze][ofrak.resource.Resource.analyze].

        :param resource: The resource that is being analyzed
        :param config: Optional config for analyzing. If an implementation provides a default,
        this default will always be used when config would otherwise be None. Note that a copy of
        the default config will be passed, so the default config values cannot be modified
        persistently by a component run.
        :return: The analysis results
        """
        raise NotImplementedError()

    def get_attributes_from_results(
        self, results: AnalyzerReturnType
    ) -> Iterable[ResourceAttributes]:
        if isinstance(results, tuple):
            attributes = results
        elif isinstance(results, ResourceAttributes):
            attributes = (results,)
        elif isinstance(results, ResourceView):
            attributes = tuple(results.get_attributes_instances().values())
        else:
            raise TypeError(
                f"Analyzer {type(self).__name__} returned an instance of type"
                f" {type(results)}; expected ResourceAttributes, Tuple[ResourceAttributes], "
                f"or ResourceView."
            )
        return attributes

    def get_outputs_as_attribute_types(self) -> Tuple[Type[ResourceAttributes], ...]:
        # All elements of the self.outputs tuple must either be subclasses of ResourceAttributes,
        # or must have ViewableResourceTag as a metaclass. This should always be true based on
        # the type annotation that is a union of two possible types of homogenous tuples
        all_outputs_are_viewable_tags = all(
            isinstance(output, ViewableResourceTag) for output in self.outputs
        )
        all_outputs_are_resource_attributes = all(
            issubclass(output, ResourceAttributes) for output in self.outputs
        )

        if all_outputs_are_viewable_tags and not all_outputs_are_resource_attributes:
            outputs = []
            for output in self.outputs:
                outputs += list(cast(ViewableResourceTag, output).composed_attributes_types)
            return tuple(outputs)
        elif not all_outputs_are_viewable_tags and all_outputs_are_resource_attributes:
            return cast(Tuple[Type[ResourceAttributes]], self.outputs)
        else:
            raise TypeError(
                f"Analyzer {type(self).__name__} has outputs that are either a tuple of "
                f"non-homogenous types, and/or have an element of a type other than "
                f"ViewableResourceTag and Type[ResourceAttributes]."
            )

    @classmethod
    def get_default_config(cls) -> Optional[CC]:
        return cls._get_default_config_from_method(cls.analyze)

    async def _run(self, resource: Resource, config: CC):
        if resource.has_component_run(self.get_id(), self.get_version()):
            return self._log_component_has_run_warning(resource)
        if resource.has_component_run(self.get_id()):
            self._log_component_has_run_warning(resource)
            raise NotImplementedError(
                "If the component has already run (but on a different "
                "version), we should remove the dependencies"
            )
        analysis_results = await self.analyze(resource, config)
        attributes = self.get_attributes_from_results(analysis_results)
        for attrs in attributes:
            resource.add_attributes(attrs)

        resource.add_component(self.get_id(), self.get_version())
        attribute_types = self.get_outputs_as_attribute_types()
        for attribute_type in attribute_types:
            resource.add_component_for_attributes(self.get_id(), self.get_version(), attribute_type)
