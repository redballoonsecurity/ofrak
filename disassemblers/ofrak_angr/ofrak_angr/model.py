from dataclasses import dataclass
from angr.project import Project
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource_view import ResourceView


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AngrAnalysis(ResourceAttributes):
    project: Project

@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AngrDecompilationAnalysis(ResourceAttributes):
    decompilation: str

class AngrAnalysisResource(ResourceView):
    pass
