from dataclasses import dataclass
from typing import Type, Tuple, Optional

from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.tag_model import ResourceTag


@dataclass
class JobAnalyzerRequest:
    job_id: bytes
    resource_id: bytes
    attributes: Type[ResourceAttributes]
    target_tags: Tuple[ResourceTag, ...]


@dataclass
class JobComponentRequest:
    job_id: bytes
    resource_id: bytes
    component_id: bytes
    config: Optional[ComponentConfig] = None


@dataclass
class JobMultiComponentRequest:
    job_id: bytes
    resource_id: bytes
    components_allowed: Tuple[bytes, ...] = ()
    components_disallowed: Tuple[bytes, ...] = ()
    tags_ignored: Tuple[ResourceTag, ...] = ()
    all_unpackers: bool = False
    all_identifiers: bool = False
    all_analyzers: bool = False
    all_packers: bool = False
