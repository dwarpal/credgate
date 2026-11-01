"""Measure what BigQuery's TABLESAMPLE is estimated and billed at.

credgate checks every BigQuery query with a dry run before running it.
For TABLESAMPLE, the dry run reports the whole table, while BigQuery bills
only the sampled blocks - but blocks only exist in tables over about 1 GB.
This script measures it on a 3 GB synthetic table, created inside BigQuery
(nothing is uploaded), in the free BigQuery sandbox:

1. dry-run estimate vs bytes billed for TABLESAMPLE at several sizes, and
   for WHERE RAND() (which reads the whole column);
2. whether BigQuery's own maximumBytesBilled refuses a TABLESAMPLE query
   whose full-table estimate is above the limit but whose sample is not.

    python benchmark/bigquery_tablesample_cost.py YOUR-PROJECT-ID
    python benchmark/bigquery_tablesample_cost.py YOUR-PROJECT-ID --delete

Uses about 6 GB of the sandbox's free 1 TB of queries a month, and 3 GB of
its free 10 GB of storage (delete it afterwards with --delete).
"""

from __future__ import annotations

import sys

from google.cloud import bigquery

if len(sys.argv) < 2:
    sys.exit(__doc__)
project = sys.argv[1]
client = bigquery.Client(project=project)
dataset = f"{project}.credgate_check"
table = f"{dataset}.cost_3gb"

if "--delete" in sys.argv:
    client.delete_table(table, not_found_ok=True)
    sys.exit(f"Deleted {table}.")

client.create_dataset(dataset, exists_ok=True)
try:
    t = client.get_table(table)
except Exception:
    print("Creating a 3 GB synthetic table inside BigQuery (a minute or two)...")
    client.query(
        f"""
        CREATE TABLE `{table}` AS
        SELECT
          a * 10000 + b AS id,
          CONCAT('Called customer ', CAST(a * 10000 + b AS STRING), ', mobile 9',
                 LPAD(CAST(MOD(ABS(FARM_FINGERPRINT(CAST(a * 10000 + b AS STRING))), 1000000000)
                      AS STRING), 9, '0'),
                 ', ', REPEAT('synthetic note ', 4)) AS notes
        FROM UNNEST(GENERATE_ARRAY(0, 2999)) AS a, UNNEST(GENERATE_ARRAY(0, 9999)) AS b
        """
    ).result()
    t = client.get_table(table)
print(f"Table: {t.num_rows:,} rows, {t.num_bytes:,} bytes\n")


def run(sql: str, limit: int | None = None) -> str:
    dry = client.query(sql, job_config=bigquery.QueryJobConfig(dry_run=True, use_query_cache=False))
    config = bigquery.QueryJobConfig(use_query_cache=False)
    if limit is not None:
        config.maximum_bytes_billed = limit
    try:
        job = client.query(sql, job_config=config)
        rows = len(list(job.result()))
        result = f"{rows:>6} rows, billed {job.total_bytes_billed:>14,}"
    except Exception as e:
        reasons = "; ".join(err.get("message", "") for err in getattr(e, "errors", None) or [])
        result = f"REFUSED: {reasons or str(e)}"
    return f"estimate {dry.total_bytes_processed:>14,}  {result}"


base = f"SELECT notes FROM `{table}`"
print("1. Estimate vs billed")
for percent in (0.1, 1, 10):
    sql = f"{base} TABLESAMPLE SYSTEM ({percent} PERCENT) LIMIT 10000"
    print(f"  TABLESAMPLE {percent:>4} %   {run(sql)}")
print(f"  RAND() < 0.001        {run(f'{base} WHERE RAND() < 0.001 LIMIT 10000')}")

limit = 200 * 1024 * 1024
print(f"\n2. With BigQuery's own limit, maximumBytesBilled = {limit:,}")
print(f"  TABLESAMPLE    1 %   {run(f'{base} TABLESAMPLE SYSTEM (1 PERCENT) LIMIT 10000', limit)}")
print(f"  RAND() < 0.001        {run(f'{base} WHERE RAND() < 0.001 LIMIT 10000', limit)}")
