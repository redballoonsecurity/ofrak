import logging
from dataclasses import dataclass

from ofrak.core.filesystem import FilesystemRoot

LOGGER = logging.getLogger(__file__)


@dataclass
class SourceBundle(FilesystemRoot):
    async def add_source_file(self, code: str, path: str):
        """
        Add a source file to this bundle.

        :param code: The contents of the source file
        :param path: The relative path in the bundle where this file should be added
        """
        await self.add_file(
            path,
            code.encode(),
        )
