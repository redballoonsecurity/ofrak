from dataclasses import dataclass

from ofrak.core.magic import MagicMimePattern
from ofrak.core.zip import ZipArchive


@dataclass
class JavaArchive(ZipArchive):
    pass


MagicMimePattern.register(JavaArchive, "application/java-archive")
