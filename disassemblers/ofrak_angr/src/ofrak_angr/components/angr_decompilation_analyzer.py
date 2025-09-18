import angr
from angr.analyses.decompiler import Decompiler

from ofrak.resource import Resource
from ofrak.core.complex_block import ComplexBlock
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_angr.model import AngrAnalysis, AngrAnalysisResource
from ofrak.core.decompilation import DecompilationAnalysis, DecompilationAnalyzer


class AngrDecompilatonAnalyzer(DecompilationAnalyzer):
    targets = (ComplexBlock,)
    outputs = (DecompilationAnalysis,)

    async def analyze(self, resource: Resource, config=None) -> DecompilationAnalysis:
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
            if len(function_s) == 0:
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
            if dec.codegen is not None:
                decomp = dec.codegen.text
            else:
                decomp = "No Decompilation available"
            resource.add_tag(DecompilationAnalysis)
            return DecompilationAnalysis(decomp)
        except Exception as e:
            return DecompilationAnalysis(
                f"The decompilation for this Complex Block has failed with the error {e}"
            )
