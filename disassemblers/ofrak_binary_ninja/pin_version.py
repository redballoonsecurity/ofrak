# Copyright (c) 2015-2023 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import argparse

from binaryninja.update import (
    UpdateChannel,
    are_auto_updates_enabled,
    set_auto_updates_enabled,
    is_update_installation_pending,
    install_pending_update,
)
from binaryninja import core_version


def main(version_string: str):
    """
    Switch BinaryNinja core version based on the given "version_string".

    This implements a version switch similar to
    https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/version_switcher.py,
    albeit without needing user input.
    """
    version = get_version(version_string)
    if version.version == core_version():
        print(f"Already running {version_string}")
        return
    if are_auto_updates_enabled():
        set_auto_updates_enabled(False)
    version.update()
    if is_update_installation_pending:
        install_pending_update()
    return


def get_version(version_string: str):
    channel = list(UpdateChannel)[0]
    for version in channel.versions:
        if version.version == version_string:
            return version
    raise ValueError(f"Cannot find {version_string}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("version", type=str)
    args = parser.parse_args()
    main(args.version)
