import json
from typing import Any, Dict, Optional, Union

from ofrak.core.architecture import ProgramAttributes


class CachedAnalysisStore:
    """
    A class that contains all cached analysis that can be passed between OFRAK components without have to re-open the json file.
    """

    def __init__(self):
        self.analysis = dict()
        self.program_attributes: Optional[ProgramAttributes] = None

    def store_analysis(self, resource_id: bytes, analysis: Union[Dict, str]):
        if isinstance(analysis, str):
            with open(analysis) as fh:
                analysis = json.load(fh)
        if resource_id not in self.analysis:
            self.analysis[resource_id] = dict()
        self.analysis[resource_id]["analysis"] = analysis

    def store_program_attributes(self, resource_id: bytes, program_attributes: ProgramAttributes):
        if resource_id not in self.analysis:
            self.analysis[resource_id] = dict()
        self.analysis[resource_id]["program_attributes"] = program_attributes

    def get_analysis(self, resource_id: bytes) -> Dict[str, Any]:
        return self.analysis[resource_id]["analysis"]

    def get_program_attributes(self, resource_id: bytes) -> Optional[ProgramAttributes]:
        if "program_attributes" not in self.analysis[resource_id]:
            return None
        return self.analysis[resource_id]["program_attributes"]

    def id_exists(self, resource_id: bytes) -> bool:
        return resource_id in self.analysis
