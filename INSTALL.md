# Install OFRAK

OFRAK is best run in a Docker image. Some OFRAK features can also be run natively on MacOS.

**OFRAK uses Git LFS. This means that you must have Git LFS installed before you clone the repository!** Install Git LFS by following [the instructions here](https://git-lfs.github.com/). If you accidentally cloned the repository before installing Git LFS, `cd` into the repository and run `git lfs pull`.

## Docker Images
To build the docker image, use the `build_image.py` utility.

For example:
```bash
python3 build_image.py --config ofrak-core-dev.yml --base --finish
```

will build the base and finish Docker image using the `ofrak-core-dev.yml` configuration. If you already have a base Docker image, you can build the finish image with:

```bash
python3 build_image.py --config --finish
```

`ofrak-binary-ninja.yml` is a configuration to build an image with core OFRAK, a Binary Ninja install, and Binary Ninja OFRAK components. **You need to have a valid BinaryNinja license to build and run the image.** To build the image, the license should be placed in the project's root directory and named `license.dat`. The serial number needs to be extracted from that file into a file named `serial.txt`. This can be done with the following command:
```bash
echo $(grep "serial" license.dat | sed 's/"serial": "//g' | sed 's/",//g') > serial.txt
```

The command `python3 build_image.py --config ofrak-binary-ninja.yml --base --finish` will build an image using Docker BuildKit secrets so that neither the license nor serial number are exposed in the built Docker image.
(If [Docker BuildKit](https://docs.docker.com/develop/develop-images/build_enhancements/) is not enabled in your environment, use the `DOCKER_BUILDKIT=1` environment variable when running this command.)

The license can then be mounted into the docker container to `/root/.binaryninja/license.dat` when run:

```bash
docker run -it --mount type=bind,source="$(pwd)"/license.dat,target=/root/.binaryninja/license.dat registry.gitlab.com/redballoonsecurity/ofrak/binary-ninja bash
```

`ofrak-ghidra.yml` builds an image which include core OFRAK, a Ghidra install, and Ghidra OFRAK components. To start the Ghidra server in a container started from this image, users should run `python -m ofrak_ghidra.server start`. To stop it, run `python -m ofrak_ghidra.server stop`. Logs can be found here: `/root/.ghidra/.ghidra_10.1.2_PUBLIC/application.log`.

`ofrak-dev.yml` builds the most complete OFRAK docker image, including the core OFRAK, a Ghidra install, Ghidra OFRAK components, a Binary Ninja install, and Binary Ninja OFRAK components.
Follow the instructions above for adding a valid BinaryNinja license and for starting the Ghidra server in the container.

### Adding new packages to OFRAK build

The build script `build_image.py` expects a config file similar to `ofrak-core-dev.yml`. Each of the packages listed in `packages_paths` should have two files, `Makefile` and `Dockerstub`. Imagine we are adding a new package with the following structure:

```
ofrak_package_x
 |--Dockerstub
 |--Makefile
 |--setup.py
 |--ofrak_package_x_python_module
     |...
```

`Makefile` must contain a rule `dependencies`. This rule should take care of any setup that needs to be done for that package before the docker build.

`Dockerstub` should read as a normal Dockerfile, only without a base image specified at the top. During build, all packages' `Dockerstub`s will be concatenated, so specifying a base image is unnecessary. This file should contain all of the steps necessary to install this package in a docker image.

The build relies on the following assumptions:

* `Dockerstub` and `Makefile` should not use any relative paths which go into the parent directory of `ofrak_package_x` because at build time that parent directory will not be the same.

* All rules in `Makefile` should assume the working directory is `ofrak_package_x` (but at a different path as explained above)

* `Dockerstub` should be written assuming the build context is the parent directory of `ofrak_package_x`. Do not assume anything is present in the build context besides the contents of `ofrak_package_x` and what `Makefile` adds to `ofrak_package_x` in the `dependencies` rule.

## MacOS
Core OFRAK can be run locally on MacOS.

It is recommended that you create a virtual environment in which to install the code:
```bash
    % python3 -m venv ofrak-venv
    % source ofrak-venv/bin/activate
```

1. Use homebrew to install required libraries and executables:
    ```bash
    brew install apktool binwalk cmake java libmagic lzop p7zip qemu squashfs rar unar wget
    ```
    * OFRAK uses `apktool`, `java`, and `wget` to install `uber-apk-signer` for unpacking and packing APK files.
    * OFRAK uses `binwalk` for analyzing packed binary files.
    * OFRAK uses `cmake` to install a custom branch of `keystone-engine`.
    * OFRAK uses the `libmagic` library is needed for `python-magic`, which automatically determines which packers/unpackers to use with binaries.
    * OFRAK uses the `lzop` command line utility for packing/unpacking LZO archives
    * OFRAK uses the 7-zip command line utility for packing/unpacking 7z archives
    * OFRAK uses the `qemu-system-i386` command line utility (and other `qemu` commands) for testing the `BzImage` packer and unpacker
    * OFRAK uses the `mksquashfs` command line utility for packing/unpacking SquashFS filesystems.
    * OFRAK uses the `rar` and `unar` command line utilities for packing/unpacking RAR archives
2.  The following script can then be used to install keystone engine:
    ```bash
    #!/usr/bin/env bash
    set -e
    cd /tmp
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
    ```
3. The custom branch of `capstone-engine` can be installed using the following script:
    ```bash
    #!/usr/bin/env bash
    set -e
    cd /tmp
    git clone https://github.com/rbs-forks/capstone.git
    cd capstone
    git checkout 2021.09.01
    ./make.sh
    sudo ./make.sh install
    cd bindings/python
    make install3
    ```
4. The `uber-apk-signer` for unpacking and packing APK filescan be installed using the following script:
    ```bash
    brew install wget apktool java
    echo 'export PATH="/usr/local/opt/openjdk/bin:$PATH"' >> ~/.zshrc
    wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.0.0/uber-apk-signer-1.0.0.jar -O /usr/local/bin/uber-apk-signer.jar
    ```
5. Install core OFRAK and its dependencies:
    ```
    INSTALL_TARGET=develop
    make -C ofrak_core $INSTALL_TARGET
    ```
6. If you are planning to contribute to OFRAK, install the pre-commit hooks. For more information, see the [contributor guide](docs/contributor-guide/getting-started.md).
    ```
    python3 -m pip install --user pre-commit
    pre-commit install
    ```
