import pytest
from angr import Project

from ofrak import OFRAKContext
from ofrak.core import File
from ofrak.service.serialization.serializers.serializer_i import SerializerInterface
from ofrak_angr.model import AngrAnalysis
from ofrak_angr.serializer import AngrAnalysisSerializer


@pytest.fixture
def serializer():
    return AngrAnalysisSerializer()


def test_angr_project_serializer(
    ofrak_context: OFRAKContext, hello_world_elf: bytes, serializer: SerializerInterface
):
    root = ofrak_context.create_root_resource("hello_world", hello_world_elf, (File,))
    root.identify()
    angr_analysis = root.analyze(AngrAnalysis)

    serialized_project = serializer.obj_to_pjson(angr_analysis.project, Project)
    assert serialized_project is None

    with pytest.raises(NotImplementedError):
        _ = serializer.pjson_to_obj(serialized_project, Project)
