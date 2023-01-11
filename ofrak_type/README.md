# OFRAK
OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform that combines the ability to unpack, analyze, modify, and repack binaries.


# Package: ofrak_type

```
OFRAK
└───ofrak
└───ofrak_type  <-- //YOU ARE HERE//
│   └───architecture
│   └───bit_width
│   └───endianness
│   └───error
│   └───memory_permissions
│   └───range
└───ofrak_io
└───ofrak_patch_maker
└───ofrak_tutorial
```

This package contains primitive types used across OFRAK packages, including:

- `Range`, an object used to represent a range of integers. Especially common when representing memory ranges.
- `InstructionSet`, `SubInstructionSet`, `InstructionSetMode`, and `Processor`, enum classes representing various architecture information.
- `BitWidth` and `Endianness` for indicating data representations.
- `NotFoundError`, `AlreadyExistError`, `InvalidStateError`, and `InvalidUsageError`, which each represent a general type of error not covered by Python's built in exception classes.
- `MemoryPermissions`, an enum class of memory access permissions R, W, X, and valid combinations of such.

## Testing
This package maintains 100% test coverage of statements.

## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro or Enterprise License. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation, which can be viewed at <https://ofrak.com/docs>.
