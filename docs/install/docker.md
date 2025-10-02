# Use Docker

**Best for**: Users who want a comprehensive, consistent environment with all dependencies included.

**Advantages**:
- All OFRAK dependencies (including disassemblers and external tools) are pre-installed
- Provides consistent environment across different platforms
- Minimal configuration needed

**Limitations**:
- Requires Docker installation
- Larger download size compared to PyPI
- Slight learning curve for Docker commands

## Prerequisites

- Docker installed and running ([Get Docker](https://www.docker.com/get-started))
- Python 3.9+
- Git with [Git LFS](https://git-lfs.github.com/) installed ([installation instructions](https://github.com/git-lfs/git-lfs#installing))
- make

## Build Your Own Image

```bash
# Clone repository
git clone https://github.com/redballoonsecurity/ofrak.git
cd ofrak

# Install build dependencies
make docker-requirements

# Build image (choose config)
python3 build_image.py --config ofrak-ghidra.yml --base --finish
```

### Available Configurations

Each image consists of a "base" image and a "finish" image:

- **Base image**: Contains all dependencies
- **Finish image**: Contains the OFRAK package itself

This separation allows you to quickly rebuild just the finish image with the latest OFRAK code without rebuilding all dependencies.

**Configuration options**:

| Configuration | Description |
|---------------|-------------|
| `ofrak-core-dev.yml` | Core OFRAK with main components and dependencies only (no disassemblers) |
| `ofrak-angr.yml` | Core OFRAK + angr disassembler backend and components |
| `ofrak-ghidra.yml` | Core OFRAK + Ghidra disassembler backend and components (recommended for most users) |
| `ofrak-binary-ninja.yml` | Core OFRAK + Binary Ninja disassembler backend. **Requires Binary Ninja license** - see [Binary Ninja setup guide](../user-guide/disassembler-backends/binary_ninja.md) |
| `ofrak-tutorial.yml` | Core OFRAK + Ghidra + interactive Jupyter tutorial notebooks |
| `ofrak-dev.yml` | Most complete image with Core OFRAK + Ghidra + Binary Ninja. **Requires Binary Ninja license** |

### Rebuild Only OFRAK (Skip Dependencies)

If you've already built a base image and only want to update OFRAK itself:

```bash
python3 build_image.py --config ofrak-ghidra.yml --finish
```

This rebuilds just the finish image without rebuilding all dependencies, which is much faster.

## Use OFRAK Interactively From Docker

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

For an interactive OFRAK example, follow along with the [Getting Started Guide](../getting-started.md) inside the container.

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

## Useful Docker Commands

Docker provides very extensive [documentation](https://docs.docker.com/) for getting started, as well as a [detailed reference](https://docs.docker.com/engine/reference/commandline/cli/) for the Docker command line interface (CLI).

Of the many Docker CLI commands, some of the most important for running containers from the provided OFRAK image include:

- [`docker run`](https://docs.docker.com/engine/reference/commandline/run/) starts container from an image, and runs until the provided command completes inside the container
- [`docker ps`](https://docs.docker.com/engine/reference/commandline/ps/) lists the running containers
- [`docker exec`](https://docs.docker.com/engine/reference/commandline/exec/) executes a command inside a running container
- [`docker cp`](https://docs.docker.com/engine/reference/commandline/cp/) copies files between the local filesystem and the container filesystem, which is useful for files that are not already bind-mounted in (using the `-v` or `--volume` arguments to `docker run`)
- [`docker stop`](https://docs.docker.com/engine/reference/commandline/stop/) gracefully stops a running container
- [`docker kill`](https://docs.docker.com/engine/reference/commandline/kill/) aborts a running container

## Common Usage

### Interactive Development
```bash
docker run -it -v "$(pwd):/workspace" -p 8080:80 \
  redballoonsecurity/ofrak/ghidra:latest /bin/bash
```

### Run Scripts
```bash
docker run --rm -v "$(pwd):/workspace" \
  redballoonsecurity/ofrak/ghidra:latest \
  python3 /workspace/my_script.py
```

### Unpack Files
```bash
docker run --rm -v "$(pwd):/files" \
  redballoonsecurity/ofrak/ghidra:latest \
  ofrak unpack /files/my_binary
```

## Troubleshooting
See [Install from Source Troubleshooting](source.md#troubleshooting-common-installation-issues).

Additionally:

**Port in use**: Change to `-p 8081:80`

**Permission issues**: Add `--user $(id -u):$(id -g)`

**Can't access GUI**: Check container is running with `docker ps`

**Out of memory**: Increase Docker memory limit

## Next Steps

- [Quick Start Guide](../getting-started.md#quick-start) for first commands
- [Getting Started](../getting-started.md) for tutorials 
