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
# The example bank policy ships with the R package (template for the policy editor).
mkdir -p "$root/pkg/credgate/inst/policies"
install -m 644 "$root/examples/policies/bank-default.yaml" "$root/pkg/credgate/inst/policies/bank-default.yaml"
echo "example policy synced"
# The policy editor's styles and script are shared by the R and Python
# editors; the Python editor also ships the example policy as its template.
py_editor="$root/pkg/python/src/credgate/editor/assets"
mkdir -p "$py_editor"
for f in editor.css editor.js; do
  install -m 644 "$root/pkg/credgate/inst/policy-editor/$f" "$py_editor/$f"
done
install -m 644 "$root/examples/policies/bank-default.yaml" "$py_editor/bank-default.yaml"
echo "policy editor assets synced"
