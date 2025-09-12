from collections import defaultdict
from dataclasses import dataclass, field
from typing import Set, Dict

from ofrak.model.tag_model import ResourceTag


@dataclass
class JobRunResourceTracker:
    tags_added: Set[ResourceTag] = field(default_factory=set)


@dataclass
class JobRunContext:
    trackers: Dict[bytes, JobRunResourceTracker] = field(
        default_factory=lambda: defaultdict(JobRunResourceTracker)
    )


class JobRunContextFactory:
    def create(self) -> JobRunContext:
        return JobRunContext()


@dataclass
class JobModel:
    id: bytes
    name: str
