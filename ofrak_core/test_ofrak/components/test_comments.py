from datetime import timedelta
import pytest
from hypothesis import given, HealthCheck, settings
from hypothesis.strategies import text
from ofrak.resource import Resource

from ofrak.core.comments import (
    AddCommentModifierConfig,
    AddCommentModifier,
    CommentsAttributes,
    DeleteCommentModifierConfig,
    DeleteCommentModifier,
)
from ofrak.core.magic import Magic
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range


@pytest.fixture
async def executable_resource(ofrak_context, elf_executable_file) -> Resource:
    root_resource = await ofrak_context.create_root_resource_from_file(elf_executable_file)
    return root_resource


async def test_adding_comments(executable_resource: Resource):
    """Test adding comments, including to the entire resource (range=None)."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "comment")),
    )
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 2


# We suppress the function_scoped_fixture health check because the executable_resource fixture
# doesn't need to be reset between individual runs of hypothesis (since the comment overrides
# the previous one every time).
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=timedelta(seconds=5),
)
@given(comment_str=text())
async def test_comment_content(executable_resource: Resource, comment_str: str):
    """Test comments with all kinds of string contents."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, comment_str)),
    )
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert comments[None] == comment_str


async def test_overriding_comment(executable_resource: Resource):
    """Test that adding a comment to a range with an existing comment overrides the existing comment."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "overriding_comment")),
    )
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 1
    assert comments[Range(0, 1)] == "overriding_comment"


async def test_range_validation(executable_resource: Resource):
    """Test that adding comments to out-of-bounds ranges raises an error."""
    data_len = len(await executable_resource.get_data())
    for r in [Range(0, data_len + 1), Range(data_len + 1, data_len + 2)]:
        with pytest.raises(ValueError):
            await executable_resource.run(
                AddCommentModifier,
                AddCommentModifierConfig(comment=(r, "comment")),
            )


@pytest.mark.parametrize("recursively", [True, False])
async def test_comments_survive_unpacking(executable_resource: Resource, recursively: bool):
    """Test that unpacking a resource after adding comments does not lose the comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    # Unpack the resource
    if recursively:
        component_run_result = await executable_resource.unpack_recursively()
    else:
        component_run_result = await executable_resource.unpack()
    assert len(component_run_result.resources_created) > 0
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 1


@pytest.mark.parametrize("recursively", [True, False])
async def test_comments_survive_repacking(executable_resource: Resource, recursively: bool):
    """Test that repacking a resource after adding comments does not lose the comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    # Unpack and repack the resource
    if recursively:
        await executable_resource.unpack_recursively()
        await executable_resource.pack_recursively()
    else:
        await executable_resource.unpack()
        await executable_resource.pack()
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 1


async def test_comments_survive_analyzing(executable_resource: Resource):
    """Test that analyzing a resource after adding comments does not lose the comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    # Analyze the resource
    await executable_resource.analyze(Magic)
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 1


async def test_deleting_comments(executable_resource: Resource):
    """Test deleting comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "comment")),
    )
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 2
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(comment_range=Range(0, 1)),
    )
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 1
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(comment_range=None),
    )
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert len(comments) == 0


async def test_deleting_non_existing_comment(executable_resource: Resource):
    """Test deleting a non-existing comment."""
    with pytest.raises(NotFoundError):
        await executable_resource.run(
            DeleteCommentModifier,
            DeleteCommentModifierConfig(comment_range=Range(0, 1)),
        )
