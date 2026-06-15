from dataclasses import dataclass

from binaryninja.binaryview import BinaryView
from ofrak.model.resource_model import ResourceAttributes


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class BinaryNinjaAnalysis(ResourceAttributes):
    binaryview: BinaryView
