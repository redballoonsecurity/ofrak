# Environment Setup

OFRAK is designed to run inside a [Docker](https://www.docker.com/get-started) container. As such, Docker is a prerequisite to use OFRAK.

Depending on the Docker image you are using, the preinstalled dependencies inside the image might include angr, Binary Ninja, or Ghidra. You must provide your own Binary Ninja headless license in order to use the Binary Ninja analysis backend.

Also included in the Docker image are the same example files that can be found
in the documentation. These example files can be found in `/examples`.

This environment setup guide will use the `redballoonsecurity/ofrak/ghidra` image as an example.

## Docker Images
To build the docker image, use the `build_image.py` utility.

For example:
```bash
python3 build_image.py --config ofrak-ghidra.yml --base --finish
```

will build the base and finish Docker image using the `ofrak-ghidra.yml`


## Use OFRAK Interactively

The `docker run` command creates a running container from the provided Docker
image.

```bash
docker run \
  --rm \
  --detach \
  --hostname ofrak \
  --name rbs-ofrak-interactive \
  --interactive \
  --tty \
  -p 80:80 \
  redballoonsecurity/ofrak/ghidra:latest
```

The options to the `docker run` command ensure the container is created with
the correct settings:

- `--rm` removes the container after it terminates
- `--detach` runs the container in the background
- `--hostname` names the host `ofrak` inside the container
- `--name` identifies the container by the name `rbs-ofrak-interactive` for
  other Docker commands, like `docker exec`
- `--interactive --tty` ensures the command knows it is being run inside an
  interactive terminal and not a script
- `-p 80:80` allows you to access the OFRAK GUI that the new container will serve on port 80 (if 
  you would rather access it locally on a different port, change the number on the left, i.e. 
  `9090:80`)
- `redballoonsecurity/ofrak/ghidra:latest` uses the correct image

The `redballoonsecurity/ofrak/ghidra:latest` image by default sets up a Ghidra environment and 
starts serving the OFRAK GUI as soon as it is launched. After running the above, the GUI can be 
accessed at http://localhost:80/.

To interact with the Python API, the following command drops into an interactive shell inside the 
running Docker container.

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

For an interactive OFRAK example, follow along with the [Getting Started
Guide](getting-started.md) inside the container.


## Run Scripts With OFRAK

It is also possible to write OFRAK scripts outside of the container, and then
run them with OFRAK inside the container. There are three steps to doing this:

1. Create a folder with an OFRAK script and any relevant binary assets
1. Create a container with the folder mapped in
1. Execute the script inside the container

Suppose a folder containing binary assets and an OFRAK script called
`script.py` is located at `~/myfolder`. For example, such a file structure
could be created with:

```bash
mkdir -p ~/myfolder
echo 'with open("/my_example/test.txt", "w") as f: f.write("Do OFRAK stuff. Meow!\n")' > ~/myfolder/script.py
```

To make the folder accessible from the path `/my_example` inside the Docker
container, add the following option to the `docker run` command from the
[previous section](#use-ofrak-interactively).

```
--volume ~/myfolder:/my_example
```

Then the new command to create the container from the image becomes the
following. All of the options are the same as before, except for the addition
of `--volume [...]`.

```bash
docker run \
  --rm \
  --detach \
  --hostname ofrak \
  --name rbs-ofrak \
  --interactive \
  --tty \
  --volume ~/myfolder:/my_example \
  ofrak-amp:0.1.0-pre-release \
  /bin/bash \
    -c "python -m ofrak_ghidra.server start;
        sleep infinity"
```

Now, the script can be run inside the Docker container, and any files in
`/my_example` that it creates or modifies will also be created or modified in
`~/myfolder` outside of the container. To see this, run the example script
using `docker exec`, and read the new file from outside of the container.

```bash
docker exec \
  --interactive \
  --tty \
  rbs-ofrak \
  python3 /my_example/script.py

cat ~/myfolder/test.txt
```

## Useful Docker Commands

Docker provides very extensive [documentation](https://docs.docker.com/) for
getting started, as well as a [detailed
reference](https://docs.docker.com/engine/reference/commandline/cli/) for the
Docker command line interface (CLI).

Of the many Docker CLI commands, some of the most important for running
containers from the provided OFRAK image include:

- [`docker run`](https://docs.docker.com/engine/reference/commandline/run/)
  starts container from an image, and runs until the provided command completes
  inside the container
- [`docker ps`](https://docs.docker.com/engine/reference/commandline/ps/) lists
  the running containers
- [`docker exec`](https://docs.docker.com/engine/reference/commandline/exec/)
  executes a command inside a running container
- [`docker cp`](https://docs.docker.com/engine/reference/commandline/cp/)
  copies files between the local filesystem and the container filesystem, which
  is useful for files that are not already bind-mounted in (using the `-v` or
  `--volume` arguments to `docker run`)
- [`docker stop`](https://docs.docker.com/engine/reference/commandline/stop/)
  gracefully stops a running container


<div align="right">
<img src="./assets/square_05.png" width="125" height="125">
</div>
