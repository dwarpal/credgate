#!/bin/sh
# Command line: scan and redact a Parquet file larger than memory.
#
# Requires: pip install 'credgate[arrow]'
# Run:      sh examples/shell/parquet_pipeline.sh
#
# All data is synthetic.
set -eu

python examples/python/make_synthetic_calls.py 100000 examples/data/calls.parquet

# 1. Which columns hold PII? (--json for machine-readable output, --fail to
#    stop a pipeline when PII is found)
credgate scan examples/data/calls.parquet --sample 5000

# 2. Redact the notes column; other columns are copied unchanged.
credgate redact --parquet examples/data/calls.parquet --column notes \
  --min-confidence 0.5 -o examples/data/calls_redacted_cli.parquet

# 3. The redacted file still has the structured PII columns (cust_pan,
#    mobile); scan it again to see what is left.
credgate scan examples/data/calls_redacted_cli.parquet --sample 5000
