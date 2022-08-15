# Contributing

## GitLab Merge Requests
Contributions to OFRAK should be made as a Pull Request on Github.

## Pre-commit
OFRAK uses [pre-commit](https://pre-commit.com/) to run automated tools on the code base before every commit.

Install pre-commit with the following commands:
```shell
pip3 install --user pre-commit
pre-commit install
```

Now each `git commit` will be preceded with a run of all the tools. If some of them fail, the commit will not proceed.

You can manually trigger a run of the tools on the current state of your code with:
```shell
pre-commit run --all-files
```

The pre-commit tools used by OFRAK notably include the opinionated [black](https://github.com/psf/black) formatter.

See the file `.pre-commit-config.yaml` for more details.

## Docstring Conventions
OFRAK uses [mkdocstrings](https://github.com/mkdocstrings/mkdocstrings) to generate code documentation. The following conventions are followed to keep this generated code documentation readable:

1. Docstrings use restructed text syntax.
2. Cross references to code can be added using [Markdown reference-style links](https://mkdocstrings.github.io/usage/#cross-references).
3. OFRAK [components][ofrak.component.interface] should have a class-level docstring that describes what the component does, including cross references to referenced objects. The main method of the component should also contain a docstring, but does not need to contain duplicated cross references (see [CodeRegionUnpacker][ofrak.core.code_region.CodeRegionUnpacker] for an example of this).
4. Dataclasses should include a docstring that lists its attributes using the `ivar` info field:
```python
@dataclass
class Foo:
    """
    :ivar value: the foo value
    """
    value: str
```

<div align="right">
<img src="../assets/square_05.png" width="125" height="125">
</div>
