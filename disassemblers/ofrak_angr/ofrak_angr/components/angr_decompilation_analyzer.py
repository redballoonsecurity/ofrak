from io import BytesIO
import angr
from ofrak.component.analyzer import Analyzer

from ofrak_angr.components.angr_analyzer import AngrAnalyzerConfig
from ofrak.resource import Resource
from ofrak.core.complex_block import ComplexBlock
from ofrak.service.resource_service_i import ResourceFilter

from ofrak_angr.model import AngrAnalysis, AngrDecompilationAnalysis, AngrAnalysisResource




class AngrDecompiltionAnalyzer(Analyzer[AngrAnalyzerConfig, AngrDecompilationAnalysis]):
    id = b"AngrAnalyzer"
    targets = (ComplexBlock,)
    outputs = (AngrDecompilationAnalysis,)
    
    async def analyze(
        self, resource: Resource, config: AngrAnalyzerConfig = AngrAnalyzerConfig()
    ) -> AngrDecompilationAnalysis:
        # Run / fetch angr analyzer
        root_resource = await resource.get_only_ancestor(
            ResourceFilter(tags=[AngrAnalysisResource], include_self=True)
        )
        complex_block = await resource.view_as(ComplexBlock)
        angr_analysis = await root_resource.analyze(AngrAnalysis)

        cfg = angr.analyses.analysis.AnalysisFactory(angr_analysis.project, config.cfg_analyzer)(
            **config.cfg_analyzer_args
        )
        
        function_s = [func for addr, func in angr_analysis.project.kb.functions.items() if func.addr == complex_block.virtual_address]
        if len(function_s) != 1:
            raise ValueError(f"Could not find angr function for function at address {complex_block.virtual_address}")
        function = function_s[0]
        dec = angr_analysis.project.analyses[angr.analyses.Decompiler].prep()(function, cfg=cfg.model, options=None)
        return AngrDecompilationAnalysis(dec.codgen.text)