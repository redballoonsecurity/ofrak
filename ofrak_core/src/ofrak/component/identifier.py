import logging
from abc import ABC, abstractmethod
from typing import Optional

from ofrak.component.abstract import AbstractComponent
from ofrak.model.component_model import CC
from ofrak.resource import Resource

LOGGER = logging.getLogger(__name__)


class IdentifierError(RuntimeError):
    """Base exception raised by identifiers."""


class Identifier(AbstractComponent[CC], ABC):
    """
    Identifiers are components that tag resources with specific resource tags.
    """

    @abstractmethod
    async def identify(self, resource: Resource, config: CC) -> None:
        """
        Perform identification on the given resource.

        Users should not call this method directly; rather, they should run
        [Resource.identify][ofrak.resource.Resource.identify].

        :param resource:
        :param config: Optional config for identifying. If an implementation provides a default,
        this default will always be used when config would otherwise be None. Note that a copy of
        the default config will be passed, so the default config values cannot be modified
        persistently by a component run.
        """
        raise NotImplementedError()

    @classmethod
    def get_default_config(cls) -> Optional[CC]:
        return cls._get_default_config_from_method(cls.identify)

    async def _run(self, resource: Resource, config: CC):
        if resource.has_component_run(self.get_id(), self.get_version()):
            LOGGER.debug(
                f"The {self.get_id().decode()} identifier has already been run on resource"
                f" {resource.get_id().hex()}"
            )
            return
        if resource.has_component_run(self.get_id()):
            # TODO: If the component has already ran (but on a different version), we should
            #  remove the tags it added
            LOGGER.warning(
                f"The {self.get_id().hex()} identifier has already been run on resource"
                f" {resource.get_id().hex()} under a different version. This is not "
                f"implemented yet."
            )
            raise NotImplementedError()
        await self.identify(resource, config)
        resource.add_component(self.get_id(), self.get_version())
