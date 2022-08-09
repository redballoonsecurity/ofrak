# Resource
## What is a "Resource?"

The abstract `Resource` is OFRAK's building block. Every "thing" is a `Resource`.

One of the most apt ways to explain is to "peel open" a filesystem...

- A Squashfs filesystem can be a resource.
- An ELF file, like `/bin/ls`, within the filesystem unpacked from the Squashfs (a `Resource` is a node in a tree, and can have children)
- The `.text` section within `/bin/ls`, once identified as an `Elf` and unpacked, is a `Resource`.
- The `ComplexBlock` named `main` within the `.text` section within `/bin/ls` is a `Resource`, *once unpacked*. (Seeing the pattern?)
- The first `BasicBlock` within `main`...
- The first `Instruction` within the first `BasicBlock` within `main`...

OFRAK `Component`s run directly against `Resource`s.
```python
root_resource: Resource = await context.create_root_resource_from_file(
    "./my_filesystem.cpio"
)
await root_resource.run(SomeVeryCoolAnalyzer, some_very_cool_analyzer_configuration)
```


## Resource Dependency Tracking
OFRAK tracks dependencies between resources and components: the `Resource` stores a detailed history of how each `ResourceAttributes` came to be added to that `Resource`.

The key pieces of information stored are:

- Which component added a given attributes
- The data that was accessed by that component (this implies that the created attributes depend on the data)
- Attributes of this `Resource` or another `Resource` that were accessed by that component (this implies that the attributes depend on those other attributes)

The second two are both encapsulated in `ResourceAttributeDependency`, containing a reference to the `Resource` and `ResourceAttributes` with a dependency. The method `AbstractComponent._create_dependencies` is mainly responsible for registering these dependencies when components are run.

Data and attribute dependencies are invalidated whenever an OFRAK patcher is called, specifically in the method `AbstractHLPatcherComponent._invalidate_dependencies`.

Dependency invalidation means that the `ResourceAttributeDependency.component_id` is removed from `ResourceModel.components_by_attributes` and `ResourceModel.component_versions`. This means that the next time `Resource.analyze_attributes` is called to get that `ResourceAttributes type, the component ID called to analyze those attributes will not be found, triggering a search for the analyzer to produce those attributes and running it. Note that the attributes are **not** actually removed from the resource, which means get_attributes will still return the existing value.

<div align="right">
<img src="../assets/square_02.png" width="125" height="125">
</div>
