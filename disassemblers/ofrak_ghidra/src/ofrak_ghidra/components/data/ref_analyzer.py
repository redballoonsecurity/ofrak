import logging
import os
from collections import defaultdict
from typing import Tuple, List, DefaultDict

from ofrak.core.data import ReferencedDataAttributes
from ofrak.core.program import ReferencedDataAnalyzer
from ofrak.resource import Resource
from ofrak_ghidra.constants import CORE_OFRAK_GHIDRA_SCRIPTS
from ofrak_ghidra.ghidra_model import OfrakGhidraMixin, OfrakGhidraScript

LOGGER = logging.getLogger(__name__)


class GhidraReferencedDataAnalyzer(ReferencedDataAnalyzer, OfrakGhidraMixin):
    """
    Analyzer to get all data references in the program
    """

    get_data_refs_script = OfrakGhidraScript(
        os.path.join(CORE_OFRAK_GHIDRA_SCRIPTS, "GetDataRefs.java")
    )

    async def analyze(self, resource: Resource, config=None) -> Tuple[ReferencedDataAttributes]:
        referenced_datas: List[int] = []
        data_referenced_by_func: DefaultDict[int, List[int]] = defaultdict(list)

        for data_ref_info in await self.get_data_refs_script.call_script(resource):
            data_start = data_ref_info["data_address"]
            referencing_funcs = data_ref_info["xrefs"]

            data_idx = len(referenced_datas)
            referenced_datas.append(data_start)
            for func in referencing_funcs:
                data_referenced_by_func[func].append(data_idx)
                LOGGER.debug(f"adding reference to data 0x{data_start:x} for func 0x{func:x}")

        referencing_funcs = list(data_referenced_by_func.keys())
        edges = list()
        for i, func in enumerate(referencing_funcs):
            edges.extend([(i, j) for j in data_referenced_by_func[func]])

        return (
            ReferencedDataAttributes(
                tuple(referencing_funcs),
                tuple(referenced_datas),
                tuple(edges),
            ),
        )
