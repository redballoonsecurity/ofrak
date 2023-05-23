from dataclasses import dataclass

try:
    from binaryninja.binaryview import BinaryView
except ImportError:
    BinaryView = None
from ofrak.model.resource_model import ResourceAttributes


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class BinaryNinjaAnalysis(ResourceAttributes):
    binaryview: BinaryView
