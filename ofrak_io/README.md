# OFRAK
OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform that combines the ability to unpack, analyze, modify, and repack binaries.


# Package: ofrak_io

```
OFRAK
└───ofrak
└───ofrak_type
└───ofrak_io  <-- //YOU ARE HERE//
│   └───batch_manager.py
│   └───deserializer.py
│   └───serializer.py
│   └───stream_capture.py
└───ofrak_patch_maker
└───ofrak_tutorial
```

This package contains some generally useful classes related to I/O, used in OFRAK.

This package contains the following modules:
- `ofrak_io.stream_capture`: this module contains `StreamCapture`, a class which is useful for capturing standard out/error of C processes called in Python
- `ofrak_io.serializer` and `ofrak_io.deserializer`: these modules are base utilities for serializing and deserializing binary data.
- `ofrak_io.batch_manager`: this module contains `AbstractBatchManager`, a base class which aims to streamline batching numerous requests over some I/O channel.

## Testing
This package maintains 100% test coverage of statements.

## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro License, which for a limited period is available for a free 6-month trial. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation, which can be viewed at <https://ofrak.com/docs>.
