from abc import ABC, abstractmethod
from dataclasses import dataclass

from ofrak.resource import Resource
from ofrak.resource_view import ResourceView

from ofrak.component.analyzer import Analyzer
from ofrak.core.complex_block import ComplexBlock


@dataclass
class DecompilationAnalysis(ResourceView):
    decompilation: str


class DecompilationAnalyzer(Analyzer[None, DecompilationAnalysis], ABC):
    """
    Analyze a [complex block][ofrak.core.complex_block.ComplexBlock] and extract its decompilation
    as a string.
    """

    targets = (ComplexBlock,)
    outputs = (DecompilationAnalysis,)
    id = b"DecompilationAnalyzer"

    @abstractmethod
    async def analyze(self, resource: Resource, config=None) -> DecompilationAnalysis:
        """
        Analyze a complex block resource and extract its decompilation as a string.

        :param resource: the complex block resource
        :param config:

        :return: the decompilation
        """
        raise NotImplementedError()
