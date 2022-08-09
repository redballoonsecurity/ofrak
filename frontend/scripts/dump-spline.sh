#!/bin/bash

# This script dumps a Spline file from links such as the following:
# https://my.spline.design/untitled-be613c23a5b45b63188f8bb3a1c04b6e/
#
# Spline (https://spline.design/) is a tool for designing web-friendly 3D
# animations. It was used to create the loading animations for the OFRAK App.
# Spline projects can be exported as URLs, which can then be included as
# <iframe> elements in a page. In the interest of not making HTTP requests to
# external sources when users load OFRAK, this script dumps the animation
# assets so they can be used offline.
#
# Spline export pages have a call to `app.start` and pass a list of bytes. This
# script extracts the list of bytes using regular expressions. Then, it uses
# Python to parse the list of bytes as JSON and print it as actual bytes.

set -e

# Print the usage if no arguments are supplied, or if the user passes "-h" or
# "--help" as the first argument. The usage is printed to stderr
if [ "$#" -lt 1 ] || [ "${1}" = "-h" ] || [ "${1}" = "--help" ]; then
  (
    echo ""
    echo "Usage: ${0} <Spline project URL> [output path]"
    echo ""
  ) 1>&2
  exit 1

# Dump the data to stdout if no output file is supplied, or if the output
# argument is "-"
elif [ "$#" = 1 ] || [ "${2}" = "-" ]; then
  curl "${1}" \
    | grep "app\.start" \
    | grep --extended-regexp --only-matching "\[(\d+, ?)*(\d+)?\]" \
    | python3 -c 'import json, sys; sys.stdout.buffer.write(bytes(json.load(sys.stdin)))'

# If an output file is provided, dump the data to the output file
else
  curl "${1}" \
    | grep "app\.start" \
    | grep --extended-regexp --only-matching "\[(\d+, ?)*(\d+)?\]" \
    | python3 -c 'import json, sys; sys.stdout.buffer.write(bytes(json.load(sys.stdin)))' \
    > "${2}"
fi
