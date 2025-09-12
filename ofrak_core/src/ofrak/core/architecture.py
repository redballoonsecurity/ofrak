from dataclasses import dataclass

from ofrak.model.resource_model import ResourceAttributes

from ofrak_type.architecture import ArchInfo


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ProgramAttributes(ResourceAttributes, ArchInfo):
    """
    Analyzer output containing architecture attributes of a program.

    """
