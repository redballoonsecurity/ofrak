from dataclasses import dataclass
import angr
from angr.analyses.decompiler import Decompiler
from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.resource_view import ResourceView

from ofrak.resource import Resource
from ofrak.core.complex_block import ComplexBlock
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_angr.model import AngrAnalysis, AngrAnalysisResource


@dataclass
class AngrDecompilationAnalysis(ResourceView):
    decompilation: str


class AngrDecompilationAnalysisIdentifier(Identifier):
    id = b"AngrDecompilationAnalysisIdentifier"
    targets = (ComplexBlock,)

    async def identify(self, resource: Resource, config=None):
        resource.add_tag(AngrDecompilationAnalysis)


class AngrDecompilatonAnalyzer(Analyzer[None, AngrDecompilationAnalysis]):
    id = b"AngrDecompilationAnalyzer"
    targets = (ComplexBlock,)
    outputs = (AngrDecompilationAnalysis,)

    async def analyze(self, resource: Resource, config: None) -> AngrDecompilationAnalysis:
        # Run / fetch angr analyzer
        try:
            root_resource = await resource.get_only_ancestor(
                ResourceFilter(tags=[AngrAnalysisResource], include_self=True)
            )
            complex_block = await resource.view_as(ComplexBlock)
            angr_analysis = await root_resource.analyze(AngrAnalysis)

            cfg = angr_analysis.project.analyses[angr.analyses.CFGFast].prep()(
                data_references=True, normalize=True
            )

            function_s = [
                func
                for addr, func in angr_analysis.project.kb.functions.items()
                if func.addr == complex_block.virtual_address
            ]
            if len(function_s) != 1:
                # Check for thumb
                function_s = [
                    func
                    for addr, func in angr_analysis.project.kb.functions.items()
                    if func.addr == complex_block.virtual_address + 1
                ]
            if len(function_s) != 1:
                raise ValueError(
                    f"Could not find angr function for function at address {complex_block.virtual_address}"
                )
            function = function_s[0]
            dec: Decompiler = angr_analysis.project.analyses[angr.analyses.Decompiler].prep()(
                function, cfg=cfg.model, options=None
            )
            return AngrDecompilationAnalysis(dec.codegen.text)
        except Exception as e:
            return AngrDecompilationAnalysis(f"The decompilation for this Complex Block has failed with the error {e}")
