# Environment Setup & Installing OFRAK

OFRAK is best run in a [Docker](https://www.docker.com/get-started) image. Some OFRAK features can also be run natively on macOS, but the docs typically assume OFRAK is running in Docker.

**OFRAK uses Git LFS. This means that you must have Git LFS installed before you clone the repository!** Install Git LFS by following [the instructions here](https://git-lfs.github.com/). If you accidentally cloned the repository before installing Git LFS, `cd` into the repository and run `git lfs pull`.

## Docker

To build any of the Docker images, use the `build_image.py` utility, which requires the PyYAML package. For example, these commands will build a Ghidra-based Docker image using the `ofrak-ghidra.yml` configuration: 

```bash
python3 -m pip install PyYAML
python3 build_image.py --config ofrak-ghidra.yml --base --finish
```

Each image consists of a "base" image and a "finish" image. The base image includes all of the dependencies. The finish image includes the package itself. This is useful for quickly building an image containing the latest version of OFRAK without rebuilding all dependencies. 

This environment setup guide uses the `redballoonsecurity/ofrak/ghidra` image as an example image throughout, but there are several possible base image configurations:

- `ofrak-dev.yml` builds the most complete OFRAK Docker image, including the core OFRAK, a Ghidra install, Ghidra OFRAK components, a Binary Ninja install, and Binary Ninja OFRAK components. 
    - Binary Ninja will fail to install without a valid license. Follow the instructions below for adding a valid Binary Ninja license.
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
  rbs-ofrak \
  python3 /my_examples/ex1_simple_string_modification.py

# On Linux, this will print "Meow!"
./examples/assets/example_program
```

### Ghidra

- By default, in containers with Ghidra, the Ghidra server should start automatically when the container starts up.
- To manually start the Ghidra server in a container started from this image, users should run `python -m ofrak_ghidra.server start`. 
- To manually stop it, run `python -m ofrak_ghidra.server stop`. 
- Ghidra logs can be found here: `/root/.ghidra/.ghidra_10.1.2_PUBLIC/application.log`.

See [the Ghidra user guide](https://ofrak.com/docs/user-guide/ghidra.html) for more information about using Ghidra with OFRAK.

### Binary Ninja

Note that Binary Ninja is not distributed with OFRAK. Instead, if a license is present, the Docker build step will run the official headless installer using the provided license. **You need to have a valid BinaryNinja license to build and run the image.** For more details, [read the script that is run](https://github.com/redballoonsecurity/ofrak/blob/master/disassemblers/ofrak_binary_ninja/install_binary_ninja_headless_linux.sh).

To build the image, the license should be placed in the project's root directory and named `license.dat`. The serial number needs to be extracted from that file into a file named `serial.txt`. This can be done with the following command:

```bash
python3 \
  -c 'import json, sys; print(json.load(sys.stdin)[0]["serial"])' \
  < license.dat \
  > serial.txt
```

The command `python3 build_image.py --config ofrak-binary-ninja.yml --base --finish` will build an image using Docker BuildKit secrets so that neither the license nor serial number are exposed in the built Docker image. (If [Docker BuildKit](https://docs.docker.com/develop/develop-images/build_enhancements/) is not enabled in your environment, precede the `python3 build_image.py` command with `DOCKER_BUILDKIT=1`.)

See [the Binary Ninja user guide](https://ofrak.com/docs/user-guide/binary_ninja.html) for more information about using Binary Ninja wiht OFRAK.

### Useful Docker Commands

Docker provides very extensive [documentation](https://docs.docker.com/) for getting started, as well as a [detailed reference](https://docs.docker.com/engine/reference/commandline/cli/) for the Docker command line interface (CLI).

Of the many Docker CLI commands, some of the most important for running containers from the provided OFRAK image include:

- [`docker run`](https://docs.docker.com/engine/reference/commandline/run/) starts container from an image, and runs until the provided command completes inside the container
- [`docker ps`](https://docs.docker.com/engine/reference/commandline/ps/) lists the running containers
- [`docker exec`](https://docs.docker.com/engine/reference/commandline/exec/) executes a command inside a running container
- [`docker cp`](https://docs.docker.com/engine/reference/commandline/cp/) copies files between the local filesystem and the container filesystem, which is useful for files that are not already bind-mounted in (using the `-v` or `--volume` arguments to `docker run`)
- [`docker stop`](https://docs.docker.com/engine/reference/commandline/stop/) gracefully stops a running container
- [`docker kill`](https://docs.docker.com/engine/reference/commandline/kill/) aborts a running container

## macOS

Core OFRAK can be run locally on macOS.

It is recommended that you create a virtual environment in which to install the code:

```bash
python3 -m venv ofrak-venv
source ofrak-venv/bin/activate
```

1. Use homebrew to install required libraries and executables:

    ```bash
    brew install \
      apktool \
      binwalk \
      cmake \
      java \
      libmagic \
      lzop \
      pigz \
      p7zip \
      qemu \
      squashfs \
      rar \
      unar \
      wget
    ```

    - OFRAK uses `apktool`, `java`, and `wget` to install `uber-apk-signer` for unpacking and packing APK files.
    - OFRAK uses `binwalk` for analyzing packed binary files.
    - OFRAK uses `cmake` to install a custom branch of `keystone-engine`.
    - OFRAK uses the `libmagic` library for `python-magic`, which automatically determines which packers/unpackers to use with binaries.
    - OFRAK uses the `lzop` command line utility for packing/unpacking LZO archives
    - OFRAK uses the 7-zip command line utility for packing/unpacking 7z archives
    - OFRAK uses the `qemu-system-i386` command line utility (and other `qemu` commands) for testing the `BzImage` packer and unpacker
    - OFRAK uses the `mksquashfs` command line utility for packing/unpacking SquashFS filesystems.
    - OFRAK uses the `rar` and `unar` command line utilities for packing/unpacking RAR archives

    If not all of the dependencies are installed, core OFRAK will still work, but most of the components will not.

2. The following script can then be used to install `keystone`:

    ```bash
    #!/usr/bin/env bash
    set -e
    pushd /tmp
    git clone https://github.com/rbs-forks/keystone.git
    cd keystone
    git checkout 2021.09.01
    mkdir build
    cd build
    ../make-share.sh
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -G "Unix Makefiles" ..
    make -j8
    sudo make install
    cd ../bindings/python
    make install3
    pip3 install .
    popd
    ```
3. The custom branch of `capstone` can be installed using the following script:

    ```bash
    #!/usr/bin/env bash
    set -e
    pushd /tmp
    git clone https://github.com/rbs-forks/capstone.git
    cd capstone
    git checkout 2021.09.01
    ./make.sh
    sudo ./make.sh install
    cd bindings/python
    make install3
    popd
    ```
4. The `uber-apk-signer` for unpacking and packing APK files can be installed using the following script:

    ```bash
    brew install wget apktool java
    echo 'export PATH="/usr/local/opt/openjdk/bin:$PATH"' >> ~/.zshrc
    wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.0.0/uber-apk-signer-1.0.0.jar -O /usr/local/bin/uber-apk-signer.jar
    ```
5. Install core OFRAK and its dependencies:

    ```bash
    for d in ofrak_io ofrak_type ofrak_patch_maker ofrak_components ofrak; do make -C "${d}" develop; done 
    ```
6. If you are planning to contribute to OFRAK, install the pre-commit hooks. For more information, see the [contributor guide](docs/contributor-guide/getting-started.md).

    ```bash
    python3 -m pip install --user pre-commit
    pre-commit install
    ```

<div align="right">
<img src="./assets/square_05.png" width="125" height="125">
</div>
