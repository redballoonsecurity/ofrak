from abc import ABC, abstractmethod
from typing import Optional

from ofrak.component.abstract import AbstractComponent
from ofrak.model.component_model import CC
from ofrak.resource import Resource


class ModifierError(RuntimeError):
    pass


class Modifier(AbstractComponent[CC], ABC):
    """
    Modifiers are components that operate on the current state of a resource, directly
    manipulating the underlying binary data.
    """

    @abstractmethod
    async def modify(self, resource: Resource, config: CC) -> None:
        """
        Modify the given resource.

        Users should not call this method directly; rather, they should run
        [Resource.run][ofrak.resource.Resource.run].

        :param resource:
        :param config: Optional config for modification. If an implementation provides a default,
        this default will always be used when config would otherwise be None. Note that a copy of
        the default config will be passed, so the default config values cannot be modified
        persistently by a component run.
        """
        raise NotImplementedError()

    @classmethod
    def get_default_config(cls) -> Optional[CC]:
        return cls._get_default_config_from_method(cls.modify)

    async def _run(self, resource: Resource, config: CC) -> None:
        await self.modify(resource, config)
