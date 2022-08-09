import itertools
from abc import ABC
from typing import Set, Type, Tuple

from ofrak.model.resource_model import ResourceAttributes

from ofrak.model.tag_model import ResourceTag

from ofrak.component.interface import ComponentInterface

from ofrak.component.analyzer import Analyzer
from ofrak.service.component_locator_i import ComponentFilter


class ComponentWhitelistFilter(ComponentFilter):
    """
    Only allow components which belong to a specific set to be run.
    """

    whitelisted_component_ids: Set[bytes]

    def __init__(self, *whitelisted_component_ids: bytes):
        self.whitelisted_component_ids = set(whitelisted_component_ids)

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        return {c for c in components if c.get_id() in self.whitelisted_component_ids}


class ComponentTypeFilter(ComponentFilter):
    """
    Only allow components of a specific type (e.g. Analyzer) to run.
    """

    component_type: Type[ComponentInterface]

    def __init__(self, component_type: Type[ComponentInterface]):
        self.component_type = component_type

    def __repr__(self) -> str:
        return f"ComponentTypeFilter({self.component_type.__name__})"

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        return {c for c in components if isinstance(c, self.component_type)}


class ComponentTargetFilter(ComponentFilter):
    """
    Only allow components which target at least one of the tags in a set. The tags must be
    strictly equal, that is, super/subclasses of the tags are not checked.
    """

    tags: Set[ResourceTag]

    def __init__(self, *tags: ResourceTag):
        self.tags = set(tags)

    def __repr__(self) -> str:
        return f"ComponentTargetFilter({', '.join(t.__name__ for t in self.tags)})"

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        return {c for c in components if any(t in self.tags for t in c.targets)}


class AnalyzerOutputFilter(ComponentFilter):
    """
    Only allow analyzers whose outputs have some overlap with the requested outputs.
    """

    outputs: Set[Type[ResourceAttributes]]

    def __init__(self, *outputs: Type[ResourceAttributes]):
        self.outputs = set(outputs)

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        def component_is_analyzer_with_outputs(c: ComponentInterface):
            if isinstance(c, Analyzer):
                analyzer_outputs = set(c.get_outputs_as_attribute_types())
                return not analyzer_outputs.isdisjoint(self.outputs)
            return False

        return {c for c in components if component_is_analyzer_with_outputs(c)}

    def __repr__(self) -> str:
        return f"AnalyzerOutputFilter({', '.join(attr_t.__name__ for attr_t in self.outputs)})"


class ComponentMetaFilter(ComponentFilter, ABC):
    """
    Abstract class for filters containing sub-filters which must be evaluated for this filter
    to be resolved.
    """

    filters: Tuple[ComponentFilter, ...]

    def __init__(self, *filters: ComponentFilter):
        self.filters = filters


class ComponentOrMetaFilter(ComponentMetaFilter):
    """
    Only allow components which match any one of multiple filters. If there are no filters, no
    components will be filtered out.
    """

    def __repr__(self) -> str:
        return f"({' or '.join(f.__repr__() for f in self.filters)})"

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        if 0 == len(self.filters):
            return components
        else:
            return set(itertools.chain(*(f.filter(components) for f in self.filters)))


class ComponentAndMetaFilter(ComponentMetaFilter):
    """
    Only allow components which match all of multiple filters. If there are no filters, all
    components will be filtered out.
    """

    def __repr__(self) -> str:
        return f"({' and '.join(f.__repr__() for f in self.filters)})"

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        if 0 == len(self.filters):
            return set()
        for component_filter in self.filters:
            components = component_filter.filter(components)
            if not components:
                break

        return components


class ComponentPrioritySelectingMetaFilter(ComponentMetaFilter):
    """
    Selects exactly one filter to apply from a prioritized list of component filters. Only the first
    filter which allows more than zero components is applied. If no filters allow any components
    through, then this filter passes no components.

    For example, if the filters are:
    - filter 1: tag matches A, B, or C
    - filter 2: tag matches C, D, or E
    - filter 3: tag matches E, F, or G

    and the components under consideration are one targeting (E) and one targeting (F), then only
    the component targeting (E) passes this meta-filter. This is because:
    - filter 1 would filter out all components under consideration, so it's ignored;
    - filter 2 would allow one or more components (namely, the component targeting (E)), so this
    meta-filter then behaves like just filter 2 in this prioritized list.
    """

    def __repr__(self) -> str:
        return f"({' then '.join(f.__repr__() for f in self.filters)})"

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        for f in self.filters:
            components_passing_f = f.filter(components)
            if components_passing_f:
                return components_passing_f

        return set()


class ComponentNotMetaFilter(ComponentMetaFilter):
    """
    Invert the result of a child filter, that is, filter out components that would pass it and pass
    components which the child filter would filter out.
    """

    def __init__(self, child_filter: ComponentFilter):
        super().__init__(child_filter)

    def filter(self, components: Set[ComponentInterface]) -> Set[ComponentInterface]:
        return components.difference(self.filters[0].filter(components))

    def __repr__(self) -> str:
        return f"not {self.filters[0]}"
