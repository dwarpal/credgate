#!/bin/sh
# Copy the shared detection spec and the licence files (LICENSE, NOTICE,
# AUTHORS) into each package that ships them. Run after editing any of them.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
for dest in "$root/pkg/credgate/inst/spec" "$root/pkg/python/src/credgate/spec"; do
  rm -rf "$dest"
  mkdir -p "$dest"
  cp -R "$root/spec/." "$dest/"
  echo "spec synced to $dest"
done
for f in LICENSE NOTICE AUTHORS; do
  install -m 644 "$root/$f" "$root/pkg/python/$f"
done
# R packages ship the licence text via the standard "Apache License" entry;
# NOTICE and AUTHORS are installed with the package from inst/.
for f in NOTICE AUTHORS; do
  install -m 644 "$root/$f" "$root/pkg/credgate/inst/$f"
done
echo "licence files synced"
