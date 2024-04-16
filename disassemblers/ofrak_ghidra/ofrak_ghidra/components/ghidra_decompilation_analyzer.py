import os
import re


from ofrak.resource import Resource
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.decompilation import DecompilationAnalysis, DecompilationAnalyzer
from ofrak_ghidra.constants import CORE_OFRAK_GHIDRA_SCRIPTS
from ofrak_ghidra.ghidra_model import OfrakGhidraMixin, OfrakGhidraScript


def take_delimited(s, delim):
    result = ""

    if delim in s:
        idx = s.index(delim)
        result += s[: idx + 1]  # include delimeter
        s = s[idx + 1 :]

        matched_quotes = list(re.finditer(r"[^\\]%s" % delim, s))

        if len(matched_quotes) > 0:
            end = matched_quotes[0].end()
            quoted_string = s[:end]
            result += quoted_string.replace("\n", "\\n")
            s = s[end:]

    return (s, result)


def escape_strings(s):
    s_escaped = ""

    while '"' in s or "'" in s:
        (s, escaped_string) = take_delimited(s, '"')
        s_escaped += escaped_string

        (s, escaped_char) = take_delimited(s, "'")
        s_escaped += escaped_char

    s_escaped += s
    return s_escaped


class GhidraDecompilationAnalyzer(DecompilationAnalyzer, OfrakGhidraMixin):
    get_decompilation_script = OfrakGhidraScript(
        os.path.join(CORE_OFRAK_GHIDRA_SCRIPTS, "GetDecompilation.java")
    )

    async def analyze(self, resource: Resource, config: None) -> DecompilationAnalysis:
        # Run / fetch ghidra analyzer
        try:
            complex_block = await resource.view_as(ComplexBlock)
            result = await self.get_decompilation_script.call_script(
                resource, complex_block.virtual_address
            )
            print(result)

            if "decomp" in result:
                decomp = (
                    result["decomp"]
                    .replace("<quote>", "'")
                    .replace("<dquote>", '"')
                    .replace("<nl>", "\n")
                )
            else:
                decomp = "No Decompilation available"

            decomp_escaped = escape_strings(decomp)
            return DecompilationAnalysis(decomp_escaped)

        except Exception as e:
            return DecompilationAnalysis(
                f"The decompilation for this Complex Block has failed with the error {e}"
            )
