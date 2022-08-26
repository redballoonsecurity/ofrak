# OFRAK
OFRAK (Open Firmware Reverse Analysis Konsole) is a binary analysis and modification platform that combines the ability unpack, analyze, modify, and repack binaries.


# Package: ofrak_io

```
OFRAK
└───ofrak
└───ofrak_components  <-- //YOU ARE HERE//
│   └───entropy
│   └─ ... sources for many individual components
└───ofrak_type
└───ofrak_io
└───ofrak_patch_maker
└───ofrak_tutorial
```

This package contains a number of components (especially Unpackers) extending the base OFRAK. A large number are related to unpacking filesystems of various formats.

This package contains Unpackers for the following file types:
- APK
- bzip2
- CPIO
- gip
- ISO 9660
- LZMA/XZ
- LZO
- 7z
- RAR
- squashfs
- tar
- UImage
- zip
- zlib

Besides this suite of unpackers, a few other components are also included:
- An unpacker Linux device tree blobs (DTB)
- Analyzers wrapping `strings` and `binwalk`
- An analyzer to calculate Shannon entropy of binary data

## Dependencies

Many of these packages rely on 3rd party tools; as these are not Python packages, they must be installed on the host system separately.
The [Dockerstub](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_components/Dockerstub) for `ofrak_components` gives some insight how to install these for an Ubuntu system. 
Due to the large number of host dependencies, and their potential differences in behavior across host systems, we strongly recommend using the OFRAK Docker build if the components in this package interest you. Instructions for building and using that can be found [here](https://ofrak.com/docs/environment-setup.html).

## Testing
The tests for `ofrak_components` are not distributed with this package.
If you wish to run the tests, download the [OFRAK source code](https://github.com/redballoonsecurity/ofrak) and install/run the tests from there.

## License
The code in this repository comes with an [OFRAK Community License](https://github.com/redballoonsecurity/ofrak/blob/master/LICENSE), which is intended for educational uses, personal development, or just having fun.

Users interested in using OFRAK for commercial purposes can request the Pro License, which for a limited period is available for a free 6-month trial. See [OFRAK Licensing](https://ofrak.com/license/) for more information.

## Documentation
OFRAK has general documentation and API documentation, which can be viewed at <https://ofrak.com/docs>.
