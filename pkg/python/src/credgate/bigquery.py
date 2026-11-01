"""PII scans and inventories of BigQuery tables (the spec's "BigQuery tables"
rules).

BigQuery samples the table and only the sample is downloaded; a dry run
checks the cost of every query first. credgate makes no network calls of
its own: it uses the ``google.cloud.bigquery.Client`` you pass, with its
credentials and project.

    from google.cloud import bigquery
    from credgate import bigquery as cgbq

    client = bigquery.Client(project="my-project")
    cgbq.scan_pii(client, "my-project.crm.customers")
    inv = cgbq.inventory_dataset(client, "my-project.crm")
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .inventory import Inventory
from .inventory import pii_inventory as _pii_inventory
from .scan import ScanReport, _Sampled
from .scan import scan_pii as _scan_pii

MAX_BYTES = 10**9
_WHOLE = {"INT64", "INTEGER"}
_DECIMAL = {"NUMERIC", "BIGNUMERIC"}
_TEXT = {"STRING", "FLOAT64", "FLOAT"}


class CostLimitError(RuntimeError):
    """A query would process more bytes than ``max_bytes`` allows; nothing ran."""


def scan_pii(
    client: Any,
    table: Any,
    sample: int = 10000,
    min_rate: float = 0.0,
    detectors: Sequence[str] | None = None,
    sampling: str = "tablesample",
    max_bytes: int = MAX_BYTES,
) -> ScanReport:
    """Scan the columns of a BigQuery table for PII (see :func:`credgate.scan_pii`).

    Args:
        client: A ``google.cloud.bigquery.Client``.
        table: ``"project.dataset.table"``, or a table reference.
        sample: Maximum number of rows sampled.
        min_rate, detectors: As for :func:`credgate.scan_pii`.
        sampling: ``"tablesample"`` (block sampling; only sampled blocks are
            billed) or ``"rand"`` (reads and bills whole columns). Views and
            external tables always use ``"rand"``.
        max_bytes: Refuse any query estimated to process more bytes than
            this (default 1 GB); also sent to BigQuery as the billing limit.
    """
    rows = _sample(client, table, sample, sampling, max_bytes)[0]
    return _scan_pii(rows, sample=sample, min_rate=min_rate, detectors=detectors)


def pii_inventory(
    client: Any,
    table: Any,
    source: str | None = None,
    sample: int = 10000,
    min_rate: float = 0.0,
    detectors: Sequence[str] | None = None,
    sampling: str = "tablesample",
    max_bytes: int = MAX_BYTES,
) -> Inventory:
    """Record where PII is in a BigQuery table (see :func:`credgate.pii_inventory`).

    The source defaults to ``"bigquery:<project>"`` and the table name to
    ``"dataset.table"``. Other arguments as for :func:`scan_pii`.
    """
    rows, t = _sample(client, table, sample, sampling, max_bytes)
    return _pii_inventory(
        rows,
        source=source or f"bigquery:{t.project}",
        table=f"{t.dataset_id}.{t.table_id}",
        sample=sample,
        min_rate=min_rate,
        detectors=detectors,
    )


def inventory_dataset(
    client: Any,
    dataset: Any,
    source: str | None = None,
    sample: int = 10000,
    min_rate: float = 0.0,
    detectors: Sequence[str] | None = None,
    sampling: str = "tablesample",
    max_bytes: int = MAX_BYTES,
) -> Inventory:
    """The inventory of every table and view in a dataset (``"project.dataset"``).

    Stops at the first table whose query would exceed ``max_bytes``. Other
    arguments as for :func:`pii_inventory`.
    """
    out = Inventory()
    for item in client.list_tables(dataset):
        out += pii_inventory(
            client,
            item.reference,
            source=source,
            sample=sample,
            min_rate=min_rate,
            detectors=detectors,
            sampling=sampling,
            max_bytes=max_bytes,
        )
    return out


def sample_query(
    table: str,
    kind: str,
    n: int,
    fields: Sequence[tuple[str, str, str]],
    sample: int = 10000,
    sampling: str = "tablesample",
) -> tuple[str | None, list[str], str]:
    """The query that samples a table, the columns it reads and the sample
    method (spec: "BigQuery tables"). ``fields`` are (name, type, mode)."""
    if sampling not in ("tablesample", "rand"):
        raise ValueError('`sampling` must be "tablesample" or "rand".')
    read, exprs = [], []
    for name, type_, mode in fields:
        if mode == "REPEATED":
            continue
        col = _ident(name)
        if type_ in _TEXT:
            exprs.append(col)
        elif type_ in _WHOLE:
            exprs.append(f"CAST({col} AS STRING) AS {col}")
        elif type_ in _DECIMAL:
            exprs.append(f"IF({col} = TRUNC({col}), CAST({col} AS STRING), NULL) AS {col}")
        else:
            continue
        read.append(name)
    if not read:
        return None, [], "all"
    sql = f"SELECT {', '.join(exprs)} FROM {_ident(table)}"
    if n <= sample:
        return sql, read, "all"
    f = max(0.000001, min(1.0, 1.2 * sample / n))
    if sampling == "tablesample" and kind == "TABLE":
        return (
            f"{sql} TABLESAMPLE SYSTEM ({_num(100 * f)} PERCENT) LIMIT {sample}",
            read,
            ("bigquery-tablesample"),
        )
    return f"{sql} WHERE RAND() < {_num(f)} LIMIT {sample}", read, "bigquery-rand"


def _sample(client: Any, table: Any, sample: int, sampling: str, max_bytes: int) -> Any:
    t = client.get_table(table)
    full = f"{t.project}.{t.dataset_id}.{t.table_id}"
    n = t.num_rows
    if n is None:
        n = next(iter(_run(client, f"SELECT COUNT(*) FROM {_ident(full)}", max_bytes)))[0]
    fields = [(f.name, f.field_type, f.mode or "NULLABLE") for f in t.schema]
    sql, read, method = sample_query(full, t.table_type or "TABLE", n, fields, sample, sampling)
    values: dict[str, list[Any]] = {name: [] for name in read}
    if sql is not None:
        for row in _run(client, sql, max_bytes):
            for i, name in enumerate(read):
                values[name].append(row[i])
    columns = {f[0]: values.get(f[0], []) for f in fields}
    return _Sampled(columns, int(n), method), t


def _run(client: Any, sql: str, max_bytes: int) -> Any:
    """Run a query after a dry run shows it stays within ``max_bytes``."""
    from google.cloud import bigquery

    dry = client.query(sql, job_config=bigquery.QueryJobConfig(dry_run=True, use_query_cache=False))
    estimate = dry.total_bytes_processed or 0
    if estimate > max_bytes:
        raise CostLimitError(
            f"This query would process about {estimate:,} bytes, more than max_bytes = "
            f"{max_bytes:,}; nothing was run. Raise max_bytes, or use a smaller sample "
            f"(with sampling='tablesample' only sampled blocks are billed).\n{sql}"
        )
    job = client.query(sql, job_config=bigquery.QueryJobConfig(maximum_bytes_billed=max_bytes))
    return job.result()


def _ident(name: str) -> str:
    return "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"


def _num(x: float) -> str:
    return f"{x:.6f}".rstrip("0").rstrip(".")
