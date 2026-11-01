"""Check credgate's BigQuery support against real BigQuery (Python half).

Run it in the free BigQuery sandbox: no credit card, and it uses a tiny
fraction of the free monthly query allowance. It creates a dataset
`credgate_check` with 20,000 rows of synthetic identifiers (never real
data), then:

1. builds the query for each sampling mode and prints BigQuery's dry-run
   estimate next to the bytes actually billed - in particular whether a
   TABLESAMPLE query is estimated (and billed) at the sampled blocks only;
2. checks the cost limit refuses a query before it runs;
3. writes the inventory to credgate_check_python.csv.

Then run sandbox_check.R for the same checks from R, and compare the CSVs.

    gcloud auth application-default login     # once
    python examples/bigquery/sandbox_check.py YOUR-PROJECT-ID
    python examples/bigquery/sandbox_check.py YOUR-PROJECT-ID --delete   # clean up

Needs: pip install "credgate[bigquery]".
"""

from __future__ import annotations

import sys

import credgate
from credgate import bigquery as cgbq
from google.cloud import bigquery

if len(sys.argv) < 2:
    sys.exit(__doc__)
project = sys.argv[1]
client = bigquery.Client(project=project)
dataset = f"{project}.credgate_check"
table = f"{dataset}.customers"

if "--delete" in sys.argv:
    client.delete_dataset(dataset, delete_contents=True, not_found_ok=True)
    sys.exit(f"Deleted {dataset}.")

# 1. Synthetic data, loaded with a load job (the sandbox has no streaming).
client.create_dataset(dataset, exists_ok=True)
try:
    client.get_table(table)
    print(f"{table} exists; reusing it.")
except Exception:
    rows = credgate.synth_indian_pii(20000, seed=1)
    for i, r in enumerate(rows):
        r["notes"] = f"Called {r['name']}, mobile {r['mobile']}" if i % 3 == 0 else "no issues"
        r["account_no"] = int(r["bank_account"][:15])  # an INT64 column
    job = client.load_table_from_json(
        rows, table, job_config=bigquery.LoadJobConfig(autodetect=True)
    )
    job.result()
    print(f"Loaded {client.get_table(table).num_rows} synthetic rows into {table}.")

t = client.get_table(table)
fields = [(f.name, f.field_type, f.mode or "NULLABLE") for f in t.schema]
print(f"\nTable: {t.num_rows} rows, {t.num_bytes:,} bytes\n")

# 2. Estimate versus billed, per sampling mode.
print(f"{'sampling':<12} {'rows':>6} {'estimate':>14} {'billed':>14}  query")
for sampling in ("tablesample", "rand"):
    sql, _, method = cgbq.sample_query(table, t.table_type, t.num_rows, fields, 500, sampling)
    dry = client.query(sql, job_config=bigquery.QueryJobConfig(dry_run=True, use_query_cache=False))
    job = client.query(sql, job_config=bigquery.QueryJobConfig(use_query_cache=False))
    n = len(list(job.result()))
    print(
        f"{sampling:<12} {n:>6} {dry.total_bytes_processed:>14,} "
        f"{job.total_bytes_billed or 0:>14,}  {sql[:60]}..."
    )

# 3. The cost limit refuses before running.
try:
    cgbq.scan_pii(client, table, max_bytes=1)
    print("\nCost limit: NOT enforced - please report this.")
except cgbq.CostLimitError:
    print("\nCost limit: refused before running, as expected.")

# 4. The inventory.
inv = cgbq.pii_inventory(client, table, sample=500)
inv.write("credgate_check_python.csv")
print(f"\n{inv}\nWrote credgate_check_python.csv")
for r in inv:
    if r.type:
        print(f"  {r.column:<16} {r.type:<16} {r.rate:>6.1%} of {r.n_sampled}  ({r.sample_method})")
