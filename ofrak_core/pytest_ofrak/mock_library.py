from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple, Optional

from ofrak.component.analyzer import Analyzer
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from pytest_ofrak.mock_component_types import MockAnalyzer, MockUnpacker


##################################################################################
# A mock library of ResourceAttributes, Resources, and Analyzers for tests to use
##################################################################################


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AbstractionAttributesA(ResourceAttributes):
    pass


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AbstractionAttributesB(ResourceAttributes):
    pass


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AbstractionAttributesC(ResourceAttributes):
    pass


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AbstractionAttributesD(ResourceAttributes):
    pass


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class AbstractionAttributesUnknown(ResourceAttributes):
    pass


class AbstractionCommon(ResourceView):
    pass


class AbstractionP(AbstractionCommon):
    pass


class AbstractionQ(AbstractionCommon):
    pass


class AbstractionR(AbstractionCommon):
    pass


class AbstractionRR(AbstractionR):
    pass


class ITargetsRROutputsD(Analyzer[None, Tuple[AbstractionAttributesD]], ABC):
    targets = (AbstractionRR,)
    outputs = (AbstractionAttributesD,)
    id = b"TargetsRROutputsD"

    @abstractmethod
    async def analyze(
        self, resource: Resource, config: Optional[ComponentConfig]
    ) -> Tuple[AbstractionAttributesD]:
        raise NotImplementedError()


class TargetsRROutputsD(MockAnalyzer, ITargetsRROutputsD):
    pass


class ITargetsPOutputsA(Analyzer[None, Tuple[AbstractionAttributesA]], ABC):
    targets = (AbstractionP,)
    outputs = (AbstractionAttributesA,)
    id = b"TargetsPOutputsA"

    @abstractmethod
    async def analyze(
        self, resource: Resource, config: Optional[ComponentConfig]
    ) -> Tuple[AbstractionAttributesA]:
        raise NotImplementedError()


class TargetsPOutputsA(MockAnalyzer, ITargetsPOutputsA):
    pass


class ITargetsCommonOutputsA(Analyzer[None, Tuple[AbstractionAttributesA]], ABC):
    targets = (AbstractionCommon,)
    outputs = (AbstractionAttributesA,)
    id = b"TargetsCommonOutputsA"

    @abstractmethod
    def analyze(
        self, resource: Resource, config: Optional[ComponentConfig]
    ) -> Tuple[AbstractionAttributesA]:
        raise NotImplementedError()


class TargetsCommonOutputsA(MockAnalyzer, ITargetsCommonOutputsA):
    pass


class ITargetsQOutputsABC(
    Analyzer[None, Tuple[AbstractionAttributesA, AbstractionAttributesB, AbstractionAttributesC]],
    ABC,
):
    targets = (AbstractionQ,)
    outputs = (AbstractionAttributesA, AbstractionAttributesB, AbstractionAttributesC)
    id = b"TargetsQOutputsABC"

    @abstractmethod
    def analyze(
        self, resource: Resource, config: Optional[ComponentConfig]
    ) -> Tuple[AbstractionAttributesA, AbstractionAttributesB, AbstractionAttributesC]:
        raise NotImplementedError()


class TargetsQOutputsABC(MockAnalyzer, ITargetsQOutputsABC):
    pass


class IWithoutImplementation(Analyzer[None, Tuple[AbstractionAttributesA]], ABC):
    targets = (AbstractionQ,)
    outputs = (AbstractionAttributesA,)
    id = b"WithoutImplementation"

    @abstractmethod
    def analyze(
        self, resource: Resource, config: Optional[ComponentConfig]
    ) -> Tuple[AbstractionAttributesA]:
        raise NotImplementedError()


class AbstractionPUnpacker(MockUnpacker):
    targets = [AbstractionP]


class AbstractionRUnpacker(MockUnpacker):
    targets = [AbstractionR]


class AbstractionRRUnpacker(MockUnpacker):
    targets = [AbstractionRR]
