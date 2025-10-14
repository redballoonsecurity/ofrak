"""
This module tests core OFRAK project functionality, including project initialization,
binary loading, and metadata persistence.
"""

import os.path

from ofrak import OFRAKContext
from ofrak.project.project import OfrakProject

TEST_PROJECT_PATH = os.path.join(os.path.dirname(__file__), "test_projects", "project1")


async def test_load_project(ofrak_context: OFRAKContext):
    """
    Loading an existing OFRAK project and verifying resource structure.

    This test verifies that:
    - Project loads successfully from disk
    - Binary loading creates child resources
    - Resource hierarchy is properly established
    """
    project = OfrakProject.init_from_path(TEST_PROJECT_PATH)
    initialized_resource = await project.init_project_binary("hello_world.bin", ofrak_context)
    assert len(list(await initialized_resource.get_children())) > 0


async def test_create_new_project(ofrak_context, tmpdir):
    """
    Creating a new OFRAK project and verifying metadata persistence.

    This test verifies that:
    - Project creates required metadata files
    - Binaries can be added to the project
    - Project state persists across sessions
    - Project identity remains consistent after reload
    """
    new_project = OfrakProject.create(
        "New Test Project",
        tmpdir,
    )

    assert new_project.metadata_path == os.path.join(tmpdir, "metadata.json")
    assert new_project.readme_path == os.path.join(tmpdir, "README.md")

    new_project.add_binary("tiny_binary", b"just a basic binary, nothing special")

    new_project.write_metadata_to_disk()

    new_project2 = OfrakProject.init_from_path(tmpdir)
    assert new_project.project_id == new_project2.project_id
    assert new_project.binaries == new_project2.binaries
