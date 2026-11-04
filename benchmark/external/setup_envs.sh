#!/bin/bash
# One virtual environment per compared tool, with the versions measured.
# All are MIT-licensed, as are the spaCy models; nothing here is shipped
# with credgate. Needs a Python 3.12 (PYTHON312).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PY=${PYTHON312:-python3.12}
mkdir -p "$HERE/envs" && cd "$HERE/envs"
for t in presidio maskflow kavach; do
  [ -d "$t" ] || "$PY" -m venv "$t"
done
kavach/bin/python -m pip install -q --only-binary=:all: "kavach-pii==0.2.0"
maskflow/bin/python -m pip install -q --only-binary=:all: "maskflow-sdk==0.9.2" "maskflow-core==0.8.3" "maskflow-pack-india==0.6.1" "maskflow-pack-intl==0.3.2"
presidio/bin/python -m pip install -q --only-binary=:all: "presidio-analyzer==2.2.366"
maskflow/bin/python -m spacy download en_core_web_sm   # MaskFlow's names and addresses
presidio/bin/python -m spacy download en_core_web_lg   # Presidio's default model
