import dataclasses
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any, Union

import aiohttp

from ofrak import Analyzer, Resource, ResourceAttributes
from ofrak.component.analyzer import AnalyzerReturnType
from ofrak.core import ComplexBlock
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
                        {"role": "assistant" if i % 2 == 0 else "user", "content": example}
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
    # Targets ComplexBlocks, but we don't want it to run automatically
    targets = ()
    outputs = (LlmAttributes,)

    async def analyze(
        self, resource: Resource, config: LlmAnalyzerConfig = None
    ) -> AnalyzerReturnType:
        if not resource.has_tag(ComplexBlock):
            raise RuntimeError("This analyzer can only be run on complex blocks")
        await resource.unpack_recursively()
        await resource.auto_run(all_analyzers=True)

        complex_block = await resource.view_as(ComplexBlock)
        decompilation = await resource.view_as(DecompilationAnalysis)

        if config is None:
            config = LlmAnalyzerConfig("http://localhost:11434/api/chat", "llama3.2")
        config.system_prompt = "You are a reverse engineer. You return concise technical descriptions of disassembled and decompiled functions, and what they do."
        config.prompt = f"""# Disassembly
{await complex_block.get_assembly()}

# Decompilation
{decompilation.decompilation}

# Metadata
{await dump_attributes(resource)}
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
