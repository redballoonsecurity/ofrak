# OFRAK Documentation

The latest build of the OFRAK docs can be found at [ofrak.com/docs](https://ofrak.com/docs).

## Build the Docs Locally

The source for OFRAK's documentation resides in this folder (`docs`), and is built using [MkDocs](https://www.mkdocs.org/). In the parent directory, [`mkdocs.yml`](../mkdocs.yml) contains the configuration for building the docs.

Before building the docs, OFRAK and all of its dependencies must be installed and available on the Python path. 

The documentation files (`docs/` and `mkdocs.yml`) likely need to be manually copied into the Docker container. If, for example, the container name is `rbs-ofrak-interactive`, the commands to copy in the necessary files would be:

``` bash
# Run from the root of the OFRAK repo
docker cp docs/ rbs-ofrak-interactive:/
docker cp mkdocs.yml rbs-ofrak-interactive:/

# For Ghidra docs, copy them to the place MkDocs expects
docker exec -it rbs-ofrak-interactive bash -c "mkdir -p /disassemblers; ln -s /ofrak_ghidra /disassemblers/ofrak_ghidra"
```

To build the documentation locally, run one of the following commands from the root directory of the Docker (or from the root of the repo on macOS):

``` bash
# Build a copy of the docs to export
mkdocs build --site-dir generated_docs

# or

# Build and serve a the docs on a local webserver that updates when they change
mkdocs serve --dev-addr 0.0.0.0:8000
```

## Contributing to the Docs

OFRAK documentation comes from two sources: manually-written markdown files in `docs/`, and automatically-extracted from docstrings in the code. 

For writing docstrings that will display well, see the [contributor guidelines](https://ofrak.com/docs/contributor-guide/python.html#docstrings). The list of packages whose docstrings are extracted can be found [in the script that does the extraction](https://github.com/redballoonsecurity/ofrak/blob/master/docs/gen_ref_nav.py#L69-L74).

To add a markdown file to the docs, first write the documentation as a markdown file in the `docs/` directory of the repo. Then, add it to the documentation nav bar by [editing the `nav` property of `mkdocs.yml`](https://github.com/redballoonsecurity/ofrak/blob/master/mkdocs.yml#L50).