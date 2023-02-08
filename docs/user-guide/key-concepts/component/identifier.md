# Identifiers
## Overview
Identifiers are components that tag resources with specific resource tags.

The following is an example of the `MagicMimeIdentifier`, which uses libmagic file type identification to tag resources:
```python

class MagicMimeIdentifier(Identifier[None]):
    id = b"MagicMimeIdentifier"
    targets = (File,)
    _tags_by_mime: Dict[str, ResourceTag] = dict()

    async def identify(self, resource: Resource, config=None):
        _magic = await resource.analyze(Magic)
        magic_mime = _magic.mime
        tag = MagicMimeIdentifier._tags_by_mime.get(magic_mime)
        if tag is not None:
            resource.add_tag(tag)
    @classmethod
    def register(cls, resource: ResourceTag, mime_types: Union[Iterable[str], str]):
        if isinstance(mime_types, str):
            mime_types = [mime_types]
        for mime_type in mime_types:
            if mime_type in cls._tags_by_mime:
                raise AlreadyExistError(f"Registering already-registered mime type: {mime_type}")
            cls._tags_by_mime[mime_type] = resource


...

MagicMimeIdentifier.register(GenericText, "text/plain")

```

The last line of the example, `MagicMimeIdentifier.register(GenericText, "text/plain")`, registers the "text/plain" pattern as one that maps to the `GenericText` resource tag.

## Usage
Identifiers can be explicitly run using the `Resource.identify` method:
```python
await resource.identify()
```

Note that running identifiers explicitly is often not needed, as `Resource.unpack` runs all registered identifiers before running
[unpackers](unpacker.md).

<div align="right">
<img src="../../../assets/square_05.png" width="125" height="125">
</div>
