# Registering Identifier Patterns
OFRAK Contributors should implement an [Identifier][ofrak.component.identifier.Identifier] to automatically identify and label resources with a [ResourceTag][ofrak.model.tag_model.ResourceTag].

First, consider leveraging the [MagicIdentifier][ofrak.core.magic.MagicIdentifier] by registering a pattern match with either the [MagicMimePattern][ofrak.core.magic.MagicMimePattern], [MagicDescriptionPattern][ofrak.core.magic.MagicDescriptionPattern], or [RawMagicPattern][ofrak.core.magic.RawMagicPattern].

For example, consider the following magic description identification registration for [UImage][ofrak.core.uimage.UImage]:

```python
MagicDescriptionPattern.register(
    UImage, lambda s: s.startswith("u-boot legacy uImage")
)
```

This pattern (along with all other identifier patterns) will get run when the [MagicIdentifier][ofrak.core.magic.MagicIdentifier] runs, resulting in a `UImage` tag to resources matching the description.

Registering magic patterns is a good first choice, since it is the most performance-efficient.
When required, it is also possible to write custom identifiers. For an example of this, see [ApkIdentifier][ofrak.core.apk.ApkIdentifier].

### Handling External Dependencies

If the Identifier makes use of tools that are not packaged in modules installable via `pip` from 
PyPI (commonly command-line tools), these dependencies must be explicitly declared as part of the 
identifier's class declaration. See the [Components Using External Tools](./external_tools.md) doc 
for information on how to do that.

<div align="right">
<img src="../../assets/square_01.png" width="125" height="125">
</div>
