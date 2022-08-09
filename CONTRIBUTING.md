# Contributing to OFRAK

## Building the Docs
OFRAK has general documentation and API documentation.

Once OFRAK has been installed, run `make develop` in `ofrak_type`, `ofrak_io`, `ofrak_core` and `ofrak_patch_maker` to install the dependencies needed to work with this documentation source.

OFRAK's documentation is built using [MkDocs](https://www.mkdocs.org/).

`mkdocs.yml` contains the configuration information for the documentation, whose source resides in `./docs`.

To view the documents locally, from the root directory of this repository run:
```
% mkdocs serve
INFO     -  Building documentation...
INFO     -  Cleaning site directory
INFO     -  Documentation built in 0.14 seconds
INFO     -  [23:59:36] Serving on http://127.0.0.1:8000/```
```

Note that the docs must be built (or served using `mkdocs serve`) in an environment with all Python  dependencies installed.
