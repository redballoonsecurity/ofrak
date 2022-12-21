import logging
from dataclasses import dataclass

from ofrak.core.filesystem import FilesystemRoot

LOGGER = logging.getLogger(__file__)


@dataclass
class SourceBundle(FilesystemRoot):
    pass
