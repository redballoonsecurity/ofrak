import functools
from typing import Iterable, List, Set, Tuple


class ResourceTag(type):
    def __init__(cls, *args, **kwargs):
        super().__init__(*args, **kwargs)
        specificity = 0
        for base in cls.base_tags():
            specificity = max(specificity, base.tag_specificity())

        cls._specificity: int = specificity + 1

    def tag_specificity(cls) -> int:
        """
        Indicates how specific an abstraction this tag is.
        :return: The number of classes in the inheritance hierarchy between this class and
        Resource
        """
        return cls._specificity

    @functools.lru_cache(None)
    def tag_classes(cls) -> Set["ResourceTag"]:
        """
        :return: Set of parent classes (including itself) that are a subclass of a _ResourceTag but
        not the _ResourceTag class.
        """
        parents = set()
        parents.add(cls)
        for base in cls.base_tags():
            parents.update(base.tag_classes())
        return parents

    @functools.lru_cache(None)
    def base_tags(cls) -> Set["ResourceTag"]:
        """
        :return: All _ResourceTags which this tag inherits from directly (does not traverse all
        ancestors)
        """
        base_tags = set()
        for base in cls.__bases__:
            if base is not cls and isinstance(base, ResourceTag) and base.tag_specificity() > 0:
                base_tags.add(base)
        return base_tags

    @staticmethod
    def sort_tags_into_tiers(
        tags: "Iterable[ResourceTag]",
    ) -> "Tuple[Tuple[ResourceTag, ...], ...]":
        """
        Sort the given tags by specificity, and group all the ties together.

        :param tags: Tags to sort and group

        :return: Tuple of groups of tags with the same specificity, sorting all of these by the
        specificity value each group represents from least to greatest.
        """
        levels: List[List[ResourceTag]] = [[], [], [], [], [], [], [], [], [], []]
        for t in tags:
            spec = t.tag_specificity()
            if spec > len(levels):
                levels.extend([] for _ in range(spec - len(levels)))
            levels[spec].append(t)

        return tuple(tuple(level) for level in reversed(levels) if len(level) > 0)

    @classmethod  # pragma: no cover
    def caption(cls, attributes) -> str:  # pragma: no cover
        return str(cls.__name__)

    def __repr__(cls):
        return cls.__name__
