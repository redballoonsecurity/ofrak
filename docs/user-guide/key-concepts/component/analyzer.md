# Analyzers
## Overview
Analyzers are discrete components that gather and analyze specific information from the target binary, returning custom processed data results, called `ResourceAttributes`, which are useful for supplementing other components.

The following is an example of the `MagicAnalzyer`, which runs libmagic file type identification against resources:
```python

from dataclasses import dataclass

import magic
from ofrak.component.analyzer import Analyzer
from ofrak.model.resource_model import ResourceAttributes
from ofrak.core.filesystem import File
from ofrak.resource import Resource


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Magic(ResourceAttributes):
    mime: str
    descriptor: str


class MagicAnalyzer(Analyzer[None, Magic]):
    targets = (File,)
    outputs = (Magic,)

    async def analyze(self, resource: Resource, config=None) -> Magic:
        data = await resource.get_data()
        magic_mime = magic.from_buffer(data, mime=True)
        magic_description = magic.from_buffer(data)
        return Magic(magic_mime, magic_description)
```

This analyzer targets resource's with the `File` tag, and outputs `Magic`.

## Usage
### Run Analyze
The preferred way to run OFRAK Analyzers is to use `Resource.analyze`:

```python
from ofrak.resource import Resource
from ofrak.core.filesystem import File
from ofrak.core.magic import Magic


resource: Resource
assert resource.has_tag(File)
magic = await resource.analyze(Magic)
```

When `Resource.analyze` is run, OFRAK will search for and run a registered analyzer that targets `File` and returns `Magic`. If the requested analysis has already been run, OFRAK will not rerun the analysis but merely return the already-analyzed result.

### Run Explicitly
Analyzers can also be run explicitly:

```python
from ofrak.core.magic import MagicAnalyzer
from ofrak.resource import Resource


resource: Resource
await resource.run(MagicAnalyzer)
```

This manner of running analyzers can be used if the analysis results are not needed immediately.


### Recursive Analysis
It is also possible to recursively analyzers against a resource and its descendants with the `Resource.analyze_recursively` method. See [Resource](../resource.md) for more details.

<div align="right">
<img src="../../../assets/square_02.png" width="125" height="125">
</div>
