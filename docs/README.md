# OFRAK Docs

The latest build of the OFRAK docs can be found at (ofrak.com/docs)[https://ofrak.com/docs].

## Build the Docs Locally

The source for OFRAK's documentation resides in this folder (`docs`), and is built using [MkDocs](https://www.mkdocs.org/). In the parent directory, [`mkdocs.yml`](../mkdocs.yml) contains the configuration for building the docs.

Before building the docs, OFRAK and all of its dependencies must be installed and on the Python path. 

To build the documentation locally, run one of the following commands from the root directory of the Docker (or from the root of the repo on macOS):

``` bash
# Build a copy of the docs to export
mkdocs build

# or

# Build and serve a the docs on a local webserver that updates when they change
mkdocs serve
```
