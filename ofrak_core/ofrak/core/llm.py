import dataclasses
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any, Union

import aiohttp

from ofrak import Analyzer, Resource, ResourceAttributes, ResourceFilter
from ofrak.core import ComplexBlock, Program
from ofrak.core.decompilation import DecompilationAnalysis
from ofrak.core.entropy import DataSummary
from ofrak.model.component_model import ComponentConfig
from ofrak.model.viewable_tag_model import AttributesType
from ofrak_type import Range


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class LlmAttributes(ResourceAttributes):
    description: str


@dataclass
class LlmAnalyzerConfig(ComponentConfig):
    api_url: str
    model: str
    api_key: Optional[str] = None
    prompt: Optional[str] = None
    system_prompt: str = "You are a reverse engineer. You return concise technical descriptions of binaries, and what they do."
    examples: Optional[List[str]] = None


class LlmAnalyzer(Analyzer[LlmAnalyzerConfig, LlmAttributes]):
    """
    This analyzer uses a Large Language Model (LLM) to describe the resource being analyzed in natural language.

    The analyzer works with local models run using Ollama or remote models such as OpenAI's ChatGPT. To run a local
    Ollama instance, use the following commands:

    ```
    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull llama3.2
    ollama serve
    # Use http://localhost:11434/api/chat as the API URL in the analyzer config
    ```

    It is advisable to tune the results by editing the system prompt and/or adding examples. The `prompt` field of the
    config should only be overridden by other analyzers that want to use the LLM in a more specific way (e.g., the
    `LlmFunctionAnalyzer` is specifically for analyzing decompilation output).
    """

    targets = ()
    outputs = (LlmAttributes,)

    async def analyze(self, resource: Resource, config: LlmAnalyzerConfig = None) -> LlmAttributes:
        if config is None:
            config = LlmAnalyzerConfig("http://localhost:11434/api/chat", "llama3.2")

        headers = (
            {"Authorization": f"Bearer {config.api_key}"} if config.api_key is not None else dict()
        )

        if config.prompt is None:
            prompt = f"""Tell me what the following binary is and what it does.
            
# Metadata
{await dump_attributes(resource)}

# First 100 bytes
{await hex_dump(resource)}..."""
        else:
            prompt = config.prompt

        body = {
            "model": config.model,
            "messages": [
                {
                    "role": "system",
                    "content": config.system_prompt,
                },
                *(
                    [
                        {"role": "user" if i % 2 == 0 else "assistant", "content": example}
                        for i, example in enumerate(config.examples)
                    ]
                    if config.examples is not None
                    else []
                ),
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "stream": False,
        }

        # TODO: class-wide client session instance for connection pooling
        async with aiohttp.ClientSession() as session:
            async with session.post(config.api_url, json=body, headers=headers) as response:
                response.raise_for_status()
                data = await response.json()
                if "message" in data:
                    message = data["message"]
                elif "choices" in data and data["choices"]:
                    message = data["choices"][0]["message"]
                return LlmAttributes(message["content"])


class LlmFunctionAnalyzer(Analyzer[LlmAnalyzerConfig, LlmAttributes]):
    # Targets ComplexBlock, but we don't want it to run automatically
    targets = ()
    outputs = (LlmAttributes,)

    async def analyze(self, resource: Resource, config: LlmAnalyzerConfig = None) -> LlmAttributes:
        if not resource.has_tag(ComplexBlock):
            raise RuntimeError("This analyzer can only be run on complex blocks")
        await resource.unpack_recursively()
        decompilation = await resource.view_as(DecompilationAnalysis)

        if config is None:
            config = LlmAnalyzerConfig("http://localhost:11434/api/chat", "llama3.2")
        config.system_prompt = (
            "You are a computer program for reverse engineering. You return "
            "concise technical summaries of disassembled and decompiled "
            "functions, and what they do without additional commentary. You "
            "always respond with only one or two sentences."
        )
        config.examples = None
        config.prompt = f"""# Decompilation
{decompilation.decompilation}

# Metadata
{await dump_attributes(resource)}

Describe what this function does.
"""
        await resource.run(LlmAnalyzer, config)
        return resource.get_attributes(LlmAttributes)


class LlmProgramAnalyzer(Analyzer[LlmAnalyzerConfig, LlmAttributes]):
    # Targets Program, but we don't want it to run automatically
    targets = ()
    outputs = (LlmAttributes,)

    async def analyze(self, resource: Resource, config: LlmAnalyzerConfig = None) -> LlmAttributes:
        if not resource.has_tag(Program):
            raise RuntimeError("This analyzer can only be run on programs")

        await resource.unpack_recursively()
        program = await resource.view_as(Program)
        # Rough heuristic that the largest code region is probably the text section
        text_section = max(await program.get_code_regions(), key=lambda cr: cr.size)
        functions = list(
            await text_section.resource.get_descendants_as_view(
                ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
            )
        )
        # TODO: Should this be concurrent?
        # await asyncio.gather(*(function.resource.run(LlmAnalyzer, config) for function in functions))
        for function in functions:
            await function.resource.run(LlmFunctionAnalyzer, config)
        descriptions = [
            f"- {function.name}: {function.resource.get_attributes(LlmAttributes).description.splitlines()[0]}"
            for function in functions
        ]

        if config is None:
            config = LlmAnalyzerConfig("http://localhost:11434/api/chat", "llama3.2")
        config.system_prompt = (
            "You are a computer program for reverse engineering. You return "
            "concise technical summaries of disassembled and decompiled "
            "programs, and what they do without additional commentary. You "
            "always respond with only one or two sentences."
        )
        config.prompt = f"""# Functions
{chr(10).join(descriptions)}

# Metadata
{await dump_attributes(resource)}

Describe what the entire program does based on its functions and metadata.
"""
        await resource.run(LlmAnalyzer, config)
        return resource.get_attributes(LlmAttributes)


def indent(s: str, spaces: int = 2) -> str:
    return "\n".join(" " * spaces + line for line in s.splitlines())


def make_serializable(o):
    if o is None:
        return o
    elif isinstance(o, (int, float)):
        return o
    elif isinstance(o, str):
        return o
    elif isinstance(o, (list, set)):
        return [make_serializable(x) for x in o]
    elif isinstance(o, dict):
        return {make_serializable(k): make_serializable(v) for k, v in o.items()}
    elif isinstance(o, type):
        return o.__name__
    elif isinstance(o, Enum):
        return str(o)
    elif isinstance(o, bytes):
        return o.hex()
    elif dataclasses.is_dataclass(o):
        return make_serializable(dataclasses.asdict(o))
    elif isinstance(o, os.stat_result):
        return {
            name: getattr(o, name)
            for name in [
                "st_mode",
                "st_ino",
                "st_dev",
                "st_nlink",
                "st_uid",
                "st_gid",
                "st_size",
                "st_atime",
                "st_mtime",
                "st_ctime",
            ]
            if hasattr(o, name)
        }
    else:
        return repr(o)


def serialize(o: Optional[Union[int, float, str, List[Any], Dict[Any, Any]]]) -> str:
    if o is None:
        return "null"
    elif isinstance(o, (int, float)):
        return str(o)
    elif isinstance(o, str):
        return json.dumps(o)
    elif isinstance(o, list):
        return "\n".join("- " + serialize(x) for x in o)
    elif isinstance(o, dict):
        result = []
        for k, v in o.items():
            s = serialize(v)
            if "\n" in s:
                result.append(f"{k}:\n{indent(s)}")
            else:
                result.append(f"{k}: {s}")
        return "\n".join(result)


async def dump_attributes(resource: Resource) -> str:
    model = resource.get_model()
    # The data summary is un-informative and verbose
    if DataSummary in model.attributes:
        del model.attributes[DataSummary]
    # We pretty-print the decompilation analysis
    if AttributesType[DecompilationAnalysis] in model.attributes:
        del model.attributes[AttributesType[DecompilationAnalysis]]
    return serialize(make_serializable(model.attributes))


async def hex_dump(resource: Resource) -> str:
    data = await resource.get_data(Range(0, 100))
    return " ".join(f"{b:0>2x}" for b in data)
