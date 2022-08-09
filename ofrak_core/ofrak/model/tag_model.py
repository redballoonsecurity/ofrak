import functools
from collections import defaultdict
from typing import Set, Iterable, Tuple


class ResourceTag(type):
    @functools.lru_cache(None)
    def tag_specificity(cls) -> int:
        """
        Indicates how specific an abstraction this tag is.
        :return: The number of classes in the inheritance hierarchy between this class and
        Resource
        """
        specificity = 0
        for base in cls.base_tags():
            specificity = max(specificity, base.tag_specificity())

        return specificity + 1

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
        level_dict = defaultdict(list)
        for t in tags:
            level_dict[t.tag_specificity()].append(t)

        level_list = [tuple(level_dict[level]) for level in sorted(level_dict.keys())]
        return tuple(level_list)

    def caption(cls, attributes) -> str:
        return str(cls.__name__)

    def __repr__(self):
        return self.__name__
