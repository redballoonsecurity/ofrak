# Components Using External Tools

It often makes sense to write a component which makes use of third-party tools in one way or 
another. If these tools are distributed in Python modules, the module can simply be added to the 
requirements in the OFRAK package's `setup.py` file. But for dependencies on tools which cannot be
simply installed with `pip`, OFRAK has another mechanism for the making the dependency clear to users
and easy to install.

### ComponentExternalTool

[ComponentExternalTool][ofrak.model.component_model.ComponentExternalTool] is a class that encapsulates the information 
that OFRAK tracks about an external tool which a component depends on. Each component that uses an 
external tool should include a [ComponentExternalTool][ofrak.model.component_model.ComponentExternalTool] object for that tool in its 
`external_dependencies` field (empty by default, this field does not need to be provided for 
components which do not use an external tool). The [ZipUnpacker][ofrak.core.zip.ZipUnpacker] is an example:

1. At the top of the file, the `ComponentExternalTool` is declared:

```python
UNZIP_TOOL = ComponentExternalTool(
    "unzip",
    "https://linux.die.net/man/1/unzip",
    install_check_arg="--help",
    apt_package="unzip",
    brew_package="unzip",
    choco_package="unzip",
)

```

2. In the declaration of the component itself, the tool is listed in the component's 
`external_dependencies`:

```python
class ZipUnpacker(Unpacker[None]):
    """
    Unpack (decompress) a zip archive.
    """

    targets = (ZipArchive,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNZIP_TOOL,)  # HERE

    async def unpack(self, resource: Resource, config=None):
        ...
```

And that's it! This allows OFRAK to do a couple things:
1. When a user requests a list of the non-Python OFRAK dependencies they need to install, OFRAK can 
see that `ZipUnpacker` depends on `unzip` and reports this:

```
python3 -m ofrak deps
[✓] unzip
	https://linux.die.net/man/1/unzip
	[ApkIdentifier, ZipUnpacker]
...
```

2. OFRAK can catch certain errors when the component runs which obviously arise from the dependency 
not being found, and re-raise them in a way that makes it more clear to the user they are missing a 
dependency with some hints on how to install it:

```
ofrak.component.abstract.ComponentMissingDependencyError: Missing unzip tool needed for ZipUnpacker!
	apt installation: apt install unzip
	brew installation: brew install unzip
	See https://linux.die.net/man/1/unzip for more info and installation help.
```

See the [ComponentExternalTool][ofrak.model.component_model.ComponentExternalTool] docs for a 
breakdown of the fields of that class.

### Edge Cases

One of the functions of [ComponentExternalTool][ofrak.model.component_model.ComponentExternalTool] is to provide a way for 
OFRAK to check if each dependency is installed. By default, this is done by running a command 
formed from fields of the `ComponentExternalTool`:

```python
retcode = subprocess.call([self.tool, self.install_check_arg], ...)
```

This works for most cases (the `install_check_arg` provides a lot of flexibility), but does not 
cover certain edge cases. For example, [SquashfsUnpacker][ofrak.core.squashfs.SquashfsUnpacker] requires 
specifically versions of  `unsquashfs` with the `-no-exit-code` flag. A user may already have 
`unsquashfs` installed, but an unsuitable version, so simply checking for `unsquashfs` can give a 
false negative result when a user is checking for missing dependencies.

In such cases, [ComponentExternalTool][ofrak.model.component_model.ComponentExternalTool] should be subclassed for that 
edge case dependency and its `is_tool_installed` method be overwritten. For the `unsquashfs` example:

```python

class _UnsquashfsV45Tool(ComponentExternalTool):
    def __init__(self):
        super().__init__("unsquashfs", "https://github.com/plougher/squashfs-tools.git", "")

    def is_tool_installed(self) -> bool:
        try:
            result = subprocess.run(
                ["unsquashfs", "-help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return False

        if 0 != result.returncode:
            return False

        if b"-no-exit" not in result.stdout:
            # Version 4.5+ has the required -no-exit option
            return False

        return True
```

Then the dependency on `unsquashfs` can be included in the unpacker as usual:

```python

UNSQUASHFS = _UnsquashfsV45Tool()

...


class SquashfsUnpacker(Unpacker[None]):
    """Unpack a SquashFS filesystem."""

    targets = (SquashfsFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNSQUASHFS,)

    async def unpack(self, resource: Resource, config=None):
        ...

```


<div align="right">
<img src="../../assets/square_04.png" width="125" height="125">
</div>
