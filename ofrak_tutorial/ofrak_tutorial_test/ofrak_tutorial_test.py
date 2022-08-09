from pathlib import Path

import os
from shutil import copytree

ofrak_tutorial_directory = Path(__file__).parent.parent


def test_stripped_notebook_generation(tmp_path: Path, capfd):
    """Check that the generation of stripped notebooks from the notebooks with outputs works"""
    copytree(
        ofrak_tutorial_directory / "notebooks_with_outputs", tmp_path / "notebooks_with_outputs"
    )
    should_work_retcode = os.system(
        f"make -C {ofrak_tutorial_directory} generate_stripped_notebooks"
    )
    assert should_work_retcode == 0
    captured = capfd.readouterr()
    assert "Converting notebook" in captured.err  # something happened
    assert "WARNING" not in captured.err  # ... but no warnings
