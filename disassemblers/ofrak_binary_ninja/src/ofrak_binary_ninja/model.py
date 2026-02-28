from dataclasses import dataclass

from binaryninja.binaryview import BinaryView
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource_view import ResourceView


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class BinaryNinjaAnalysis(ResourceAttributes):
    binaryview: BinaryView


class BinaryNinjaAnalysisResource(ResourceView):
    pass


class BinaryNinjaAutoLoadProject(BinaryNinjaAnalysisResource):
    pass


class BinaryNinjaCustomLoadProject(BinaryNinjaAnalysisResource):
    pass
