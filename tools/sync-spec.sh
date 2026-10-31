#!/bin/sh
# Copy the detection spec into each package that ships it.
# Run after editing anything in spec/.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
dest="$root/pkg/credgate/inst/spec"
rm -rf "$dest"
mkdir -p "$dest"
cp -R "$root/spec/." "$dest/"
echo "spec synced to $dest"
