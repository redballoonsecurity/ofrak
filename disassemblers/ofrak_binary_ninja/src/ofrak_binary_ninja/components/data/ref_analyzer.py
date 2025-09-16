import logging
from collections import defaultdict
from typing import DefaultDict, Iterable, List, Tuple

from binaryninja import BinaryView

from ofrak.core.data import ReferencedDataAttributes
from ofrak.core.program import ReferencedDataAnalyzer
from ofrak_binary_ninja.components.binary_ninja_analyzer import BinaryNinjaAnalyzer
from ofrak_binary_ninja.model import BinaryNinjaAnalysis

from ofrak.resource import Resource

LOGGER = logging.getLogger(__name__)


class BinaryNinjaReferencedDataAnalyzer(ReferencedDataAnalyzer):
    """
    Analyzer to get all data references in the program
    """

    async def analyze(self, resource: Resource, config=None) -> Tuple[ReferencedDataAttributes]:
        if not resource.has_attributes(BinaryNinjaAnalysis):
            await resource.run(BinaryNinjaAnalyzer)
        binaryview = resource.get_attributes(BinaryNinjaAnalysis).binaryview
        referenced_datas: List[int] = []
        data_referenced_by_func: DefaultDict[int, List[int]] = defaultdict(list)

        for data_start, referencing_funcs in self._binary_ninja_get_get_data_refs(binaryview):
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

    @staticmethod
    def _binary_ninja_get_get_data_refs(binaryview: BinaryView) -> Iterable[Tuple[int, List[int]]]:
        """
        Returns all the data referenced.
        """

        def get_func_refs_to_data(data_start):
            funcs = set()
            t_refs = binaryview.get_code_refs(data_start)
            for t_r in t_refs:
                funcs.add(t_r.address)
            return funcs

        data_uniq = set()
        for func in binaryview.functions:
            # check for every byte in the address range (not ideal but couldn't find a way to iterate over instruction addresses in every function)
            for addr in range(func.address_ranges[0].start, func.address_ranges[0].end):
                for start_ea in binaryview.get_code_refs_from(addr):
                    datakey = str(start_ea)
                    if datakey not in data_uniq:
                        data_uniq.add(datakey)
                        yield ((start_ea), get_func_refs_to_data(start_ea))
