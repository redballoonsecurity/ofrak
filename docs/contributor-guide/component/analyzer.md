# Writing Analyzers
To write an OFRAK [Analyzer](../../user-guide/component/analyzer.md), a contributor needs to:

1. Create a class that inherits from `ofrak.component.component_analyzer.Analyzer` with a defined `ofrak.model.component_model.CC` and `ofrak.component.component_analyzer.AnalyzerReturnType`;
2. Implement the `targets` and `outputs` to indicate what resource tags the analyzer targets and what attributes it returns (the idiomatic OFRAK way to do this is to use a field);
3. Implement the `analyze` method such that it performs analysis and returns the defined `AnalyzerReturnType`.

The following is an example of a fully-implemented OFRAK Analyzer.
```python
from dataclasses import dataclass

from ofrak.component.analyzer import Analyzer
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView


@dataclass
class Foo(ResourceView):
    pass


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class FooBar(ResourceAttributes):
    foobar: str


class FooAnalyzer(Analyzer[None, FooBar]):
    targets = (Foo,)
    outputs = FooBar

    async def analyze(self, resource: Resource, config=None) -> FooBar:
        return FooBar("foobar!")
```

### Handling External Dependencies

If the Analyzer makes use of tools that are not packaged in modules installable via `pip` from 
PyPI (commonly command-line tools), these dependencies must be explicitly declared as part of the 
analyzer's class declaration. See the [Components Using External Tools](./external_tools.md) doc for 
information on how to do that.

### Testing Analyzers
`test_ofrak.unit.analyzer.analyzer_test_case.AnalyzerTests` provides a suite of test cases that can be used to test implemented OFRAK Analyzers.

To use this test suite, a contributor should create a file, e.g. `test_foo_analyzer.py`, which should include the following:

1. An implementation of a subclass of `AnalyzerTestCase` which contains assets needed for the test: in addition to the analyzer type and expected analyzer return type, this often includes the bytes needed to create the resource. For example, `FooAnalyzerTestCase`.
2. A subclass of `PopulatedAnalyzerTestCase` for the given analyzer. For example, `PopulatedFooAnalyzerTestCase`.
3. A parametrized fixture titled `test_case` which returns the populated test cases.
4. A subclass of `AnalyzerTests`, i.e. `TestFooAnalyzer`.

See the following for an example:

```python
from dataclasses import dataclass

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from test_ofrak.unit.analyzer.analyzer_test_case import (
    AnalyzerTestCase,
    PopulatedAnalyzerTestCase,
    AnalyzerTests,
)


@dataclass
class FooAnalyzerTestCase(AnalyzerTestCase):
    resource_contents: bytes


@dataclass
class PopulatedFooAnalyzerTestCase(PopulatedAnalyzerTestCase, FooAnalyzerTestCase):
    ofrak_context: OFRAKContext
    resource: Resource

    def get_analyzer(self):
        return self.ofrak_context.component_locator.get_by_type(self.analyzer_type)


@pytest.fixture(
    params=[
        FooAnalyzerTestCase(FooAnalyzer, (FooBar("foobar!"),), b"Hello world\n")
    ]
)
async def test_case(
    request, ofrak_context: OFRAKContext, test_id: str
) -> PopulatedFooAnalyzerTestCase:
    test_case: FooAnalyzerTestCase = request.param
    resource = await ofrak_context.create_root_resource(test_id, test_case.resource_contents)
    return PopulatedFooAnalyzerTestCase(
        test_case.analyzer_type,
        test_case.expected_result,
        test_case.resource_contents,
        ofrak_context,
        resource,
    )


class TestFooAnalyzer(AnalyzerTests):
    pass

```

When pytest runs this file, it will run all of the tests in `AnalyzerTests` with the input provided from the parameterized `test_case` fixture in this file.

See `test_ofrak.unit.analyzer.test_magic_analyzer` for another example.

<div align="right">
<img src="../../assets/square_04.png" width="125" height="125">
</div>
