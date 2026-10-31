#!/bin/sh
# Redact a file on the command line before it reaches a local model.
#
# Requires: pip install credgate, and Ollama (`ollama run`), or curl for vLLM.
# Run: sh examples/shell/redact_pipeline.sh [model]   (default gemma3:1b)
#
# All data below is synthetic.
set -eu
model="${1:-gemma3:1b}"
note=$(mktemp)
trap 'rm -f "$note"' EXIT

cat > "$note" <<'EOF'
Spoke to Smt. Kavya Iyer. Aadhaar 5422 2937 1182, mobile 098765-43210.
She asked to close the fixed deposit and credit A/c 50100987654321.
EOF

echo "== What would be redacted:"
credgate preview "$note"

echo "== Redacted text sent to $model:"
credgate redact "$note"

echo "== Model reply:"
credgate redact "$note" | ollama run "$model" "Summarise this note in one sentence:"

# A CI or pre-commit guard: fail if a file still contains PII.
# credgate detect --min-confidence 0.5 --fail exported_prompts.txt
