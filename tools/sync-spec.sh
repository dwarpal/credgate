#!/bin/sh
# Copy the shared detection spec (and the licence) into each package that
# ships it. Run after editing anything in spec/.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
for dest in "$root/pkg/credgate/inst/spec" "$root/pkg/python/src/credgate/spec"; do
  rm -rf "$dest"
  mkdir -p "$dest"
  cp -R "$root/spec/." "$dest/"
  echo "spec synced to $dest"
done
cp "$root/LICENSE" "$root/pkg/python/LICENSE"
