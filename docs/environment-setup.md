# Environment Setup & Installing OFRAK

!!! warning
    OFRAK is a Python library supporting Python3.7 and up. First and foremost, make sure your Python and pip installations are for Python3.7+! Python 3.8 is recommended, as this is the version we primarily test OFRAK with, and some packages (for example, ofrak-angr) require Python >=3.8.

There are three main ways one can set up an environment to use OFRAK:

1. From [PyPI](https://pypi.org/project/ofrak/) via `pip`. 
**This is the simplest setup and generally recommended. Use this!**
2. From the [source code](https://github.com/redballoonsecurity/ofrak) via `pip` or the `setup.py`. 
This is a little more complicated, but allows one to keep with and contribute to OFRAK development.
3. By building the appropriate OFRAK [Docker](https://www.docker.com/get-started) image. 
This has the most overhead as it requires installing Docker, but provides the most consistent and comprehensive environment.


## From PyPI

As simple as running:

```shell
pip install ofrak
```

This will install the core `ofrak` package, as well as `ofrak_patch_maker`, and all of their Python dependencies.
You can verify a successful installation (listing all installed OFRAK modules and components) with the following command:

```shell
ofrak list
```

However, not all of OFRAK's dependencies can be installed via `pip install`. 
These dependencies are, however, optional, and the OFRAK code that requires them can be disabled in order avoid runtime errors.
OFRAK has a system for inspecting and installing such dependencies. See [the section on external dependencies](#handling-non-python-dependencies) for more info on that.


## From Source Code

The OFRAK source code can be pulled from [the github page](https://github.com/redballoonsecurity/ofrak):

```shell
git clone https://github.com/redballoonsecurity/ofrak.git
cd ofrak

```

**OFRAK uses Git LFS. 
This means that you must have Git LFS installed to completely clone the repository!** 
Install Git LFS by following [the instructions here](https://git-lfs.github.com/). 
You can install Git LFS before or after you clone OFRAK, but if you clone the OFRAK repo first, you will need to `cd` into the repository and run `git lfs install && git lfs pull`.


Once cloned, go into each directory in the top level and run the installation command `make develop` 
(if you do not have and do not wish to have `make` installed, try inspecting the `Makefile` in each directory to see what commands it tries to run, usually something like `pip install -e .`).
The best order to install each directory is as follows:

1. `ofrak_type`
2. `ofrak_io`
3. `ofrak_patch_maker`
4. `ofrak_core`
5. Any/all others: `frontend`, `ofrak_tutorial`, `disassemblers/ofrak_angr`, `disassemblers/ofrak_binary_ninja`, `disassemblers/ofrak_capstone`, `disassemblers/ofrak_ghidra`

You *can* skip the installation step for any of the packages above. 
Any subsequent OFRAK packages which require a non-installed package should be able to simply install it from PyPI. 
However, this will result in a somewhat confusing environment where some of the OFRAK code in your local repo is actively used by your system, and the rest is not.

Installing OFRAK from source code will not install all of OFRAK's non-Python dependencies (for same reason as when installing OFRAK from PyPI - not all of its dependencies are pip-installable).
These dependencies are, however, optional, and the OFRAK code that requires them can be disabled in order avoid runtime errors.
OFRAK has a system for inspecting and installing dependencies. See [the section on external dependencies](#handling-non-python-dependencies) for more info on that.


### Modifying OFRAK Source Code

The main advantage of installing OFRAK from source is in order to modify or add to the OFRAK code.
See the [Contributor Guide](contributor-guide/getting-started.md) for best practices and requirements (if you want to upstream your changes) and information on how to write your own OFRAK components.

## Docker

Building an OFRAK Docker image will mean you have a full environment, with all of OFRAK's dependencies fully installed.
To build any of the Docker images, use the `build_image.py` utility, which requires the PyYAML package. 
For example, these commands will build a Ghidra-based Docker image using the `ofrak-ghidra.yml` configuration: 

```bash
pip install PyYAML
python3 build_image.py --config ofrak-ghidra.yml --base --finish
```

Each image consists of a "base" image and a "finish" image. The base image includes all of the dependencies. The finish image includes the package itself. This is useful for quickly building an image containing the latest version of OFRAK without rebuilding all dependencies. 

This environment setup guide uses the `redballoonsecurity/ofrak/ghidra` image as an example image throughout, but there are several possible base image configurations:

- `ofrak-dev.yml` builds the most complete OFRAK Docker image, including the core OFRAK, a Ghidra install, Ghidra OFRAK components, a Binary Ninja install, and Binary Ninja OFRAK components. 
!!! warning 
    Binary Ninja will fail to install without a valid license. Follow the instructions [here](user-guide/disassembler-backends/binary_ninja.md) for adding a Binary Ninja license.
- `ofrak-ghidra.yml` builds an image that includes core OFRAK, a Ghidra install, and Ghidra OFRAK components. 
- `ofrak-binary-ninja.yml` is a configuration to build an image with core OFRAK, a Binary Ninja install, and Binary Ninja OFRAK components. **You need to have a valid BinaryNinja license to build and run the image.** 
- `ofrak-tutorial.yml` builds an image including core OFRAK, Ghidra, the Ghidra components, and the tutorial Jupyter Notebooks that use Ghidra.
- `ofrak-angr.yml` builds an image that contains core OFRAK, angr, and the angr OFRAK components.
- `ofrak-core-dev.yml` builds an image that only bundles core OFRAK, its main components, and their dependencies.

If you have already built a base Docker image, and only want to reinstall OFRAK (and not all of its dependencies), you can build the finish image without the `--base` argument:

```bash
python3 build_image.py --config ofrak-ghidra.yml --finish
```

### Use OFRAK Interactively From Docker

The `docker run` command creates a running container from the provided Docker image.

```bash
docker run \
  --rm \
  --detach \
  --hostname ofrak \
  --name rbs-ofrak-interactive \
  --interactive \
  --tty \
  --publish 80:80 \
  redballoonsecurity/ofrak/ghidra:latest
```

The options to the `docker run` command ensure the container is created with the correct settings:

- `--rm` removes the container after it terminates
- `--detach` runs the container in the background
- `--hostname` names the host `ofrak` inside the container
- `--name` identifies the container by the name `rbs-ofrak-interactive` for other Docker commands, like `docker exec`
- `--interactive --tty` ensures the command knows it is being run inside an interactive terminal and not a script (`-it` can be used for short)
- `--publish 80:80` allows you to access the OFRAK GUI that the new container will serve on port 80 
    - If you would rather access it locally on a different port, change the number on the left, for example: `9090:80`
- `redballoonsecurity/ofrak/ghidra:latest` is the image to run

The `redballoonsecurity/ofrak/ghidra:latest` image by default sets up a Ghidra environment and starts serving the OFRAK GUI as soon as it is launched. After running the above, the GUI can be accessed at http://localhost:80/.

To interact with the Python API, the following command drops into an interactive shell inside the running Docker container.

```bash
docker exec \
  --interactive \
  --tty \
  rbs-ofrak-interactive \
  /bin/bash
```

The `docker exec` command executes a command inside of the Docker container.

- `--interactive --tty` ensures the command knows it is being run inside an
  interactive terminal and not a script
- `rbs-ofrak-interactive` enters the correct running container
- `/bin/bash` starts the shell

For an interactive OFRAK example, follow along with the [Getting Started Guide](getting-started.md) inside the container.

### Run Scripts With OFRAK in Docker

It is also possible to write OFRAK scripts outside of the container, and then run them with OFRAK inside the container. There are three steps to doing this:

1. Create a folder with an OFRAK script and any relevant binary assets
1. Create a container with the folder mapped in
1. Execute the script inside the container

Suppose we want to run one of the example scripts bundled with OFRAK. These scripts are located in the `examples/` directory of the repo. To make the folder accessible from the path `/my_examples` inside the Docker container, add the following option to the `docker run` command from the [previous section](#use-ofrak-interactively-from-docker).

```
--volume "$(pwd)/examples":/my_examples
```

Then the new command to create the container from the image becomes the following. All of the options are the same as before, except for the addition of `--volume [...]`.

```bash
docker run \
  --rm \
  --detach \
  --hostname ofrak \
  --name rbs-ofrak-interactive \
  --interactive \
  --tty \
  --volume "$(pwd)/examples":/my_examples \
  --publish 80:80 \
  redballoonsecurity/ofrak/ghidra:latest
```

Now, the scripts can be run inside the Docker container, and any files in `/my_examples` that they create or modify will also be created or modified in `examples/` outside of the container. To see this, run the example script using `docker exec`, and read the new file from outside of the container.

```bash
docker exec \
  --interactive \
  --tty \
  rbs-ofrak-interactive \
  python3 /my_examples/ex1_simple_string_modification.py

# On Linux, this will print "Meow!"
./examples/assets/example_program
```

### Useful Docker Commands

Docker provides very extensive [documentation](https://docs.docker.com/) for getting started, as well as a [detailed reference](https://docs.docker.com/engine/reference/commandline/cli/) for the Docker command line interface (CLI).

Of the many Docker CLI commands, some of the most important for running containers from the provided OFRAK image include:

- [`docker run`](https://docs.docker.com/engine/reference/commandline/run/) starts container from an image, and runs until the provided command completes inside the container
- [`docker ps`](https://docs.docker.com/engine/reference/commandline/ps/) lists the running containers
- [`docker exec`](https://docs.docker.com/engine/reference/commandline/exec/) executes a command inside a running container
- [`docker cp`](https://docs.docker.com/engine/reference/commandline/cp/) copies files between the local filesystem and the container filesystem, which is useful for files that are not already bind-mounted in (using the `-v` or `--volume` arguments to `docker run`)
- [`docker stop`](https://docs.docker.com/engine/reference/commandline/stop/) gracefully stops a running container
- [`docker kill`](https://docs.docker.com/engine/reference/commandline/kill/) aborts a running container


## Handling Non-Python Dependencies

Since OFRAK integrates many existing tools, it has many dependencies. 

### Ignore components with missing dependencies

Since OFRAK is modular, these components are optional. 
To quickly get started with a fresh OFRAK install, you can safely skip installing a number of dependencies by telling OFRAK not to use any components with missing dependencies.
Use the `-x` or `--exclude-components-missing-dependencies` flag for any OFRAK command-line invocations, and `exclude_components_missing_dependencies` set to `True` when setting up OFRAK in a Python script:

```python
ofrak = OFRAK(
    # other arguments...
    exclude_components_missing_dependencies=True,
)

# rest of script
```

**Keep in mind that this means OFRAK will not be able to use those components!**
For example, if you do not have `pigz` installed, the `GzipUnpacker` and `GzipPacker` will not be able to run.
The `-x` CLI flag and `exclude_components_missing_dependencies` Python flag will ensure that OFRAK won't try to run them and raise a runtime error, but OFRAK still won't be able to unpack or repack gzip data.

### Installing missing dependencies

OFRAK dependencies come in three "tiers":

1. Python packages which can be installed from PyPI.
2. Packages available through standard package managers like `apt` or `brew`.
3. Everything else. These tools have non-standard installation steps.

The easiest dependencies are those which can be installed from PyPI. These are simply included in the requirements for the OFRAK Python packages which require them. 
Simply by installing an OFRAK Python package, these dependencies will also be installed with no further effort required.
The rest of this section deals with dependencies in the second two tiers.

The second two types of dependencies can be listed with the `deps` command:

```shell
ofrak deps --missing-only

```

This will give a printout listing each missing dependency (very often a tool required for packing or unpacking some type of file) and some basic info about it, including:

- Name

- Website

- Which component(s) depend on it

This is helpful in determining whether you want to skip installing one or more dependencies, since if you don't expect to need the component(s) requiring a dependency, you can skip it.

#### Dependencies available through other package managers

Some dependencies cannot be installed as part of the `pip install` procedure, but there are packages available for them through common package managers like `apt` or `brew`.
OFRAK can report these packages and list their `apt` or `brew` packages, so you can easily install those packages.

On a Ubuntu system, you can usually do:

```shell
ofrak deps --packages-for apt | xargs apt install -y

```

Or on a Mac, you can run:

```shell
ofrak deps --packages-for brew | xargs brew install -y

```

Each of these commands will collect all OFRAK dependencies with packages installable through the respective package manager, then pipe all those packages names to the package manager's install command.
In this, way a good chunk of OFRAK's dependencies can be installed quickly.

#### Dependencies with non-standard installation

Some dependencies don't have a standard installation package (on PyPI, `apt`, or `brew`). 
These may still be simple - for example, downloading a `.jar` file - but they can also be complicated. 
Outside of the OFRAK Docker build, OFRAK will not attempt to install these.
The `Dockerstub` files can provide a good reference for how to install something, but they are specific to the Linux environment the Docker build constructs.
You are encouraged to visit each dependency's home page (listed by the `ofrak deps` command) for the developers' recommended installation steps for your specific platform.


## Setting up to contribute

If you are interested in contributing to OFRAK, check out the [contributor guide](contributor-guide/getting-started.md) for information on what tools you should or may want to install (such as git pre-commit hooks).

<div align="right">
<img src="./assets/square_05.png" width="125" height="125">
</div>
