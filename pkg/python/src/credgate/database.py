"""PII inventories of whole databases (the spec's "Databases" rules).

Every table in the chosen schemas is sampled by the database where it can
(Postgres and Db2 ``TABLESAMPLE SYSTEM``, DuckDB a reservoir sample), and only
the sample is read. With an inventory file, the scan can resume after an
interruption, and later runs rescan only the tables that changed.

    import sqlalchemy
    from credgate.database import inventory_database

    engine = sqlalchemy.create_engine("postgresql+psycopg://reader@db/crm")
    inv = inventory_database(engine, source="postgres:crm", path="inventory.csv")

credgate makes no network calls of its own: it uses the engine you pass.
"""

from __future__ import annotations

import fnmatch
import os
import re
import warnings
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .inventory import Inventory, pii_inventory, read_inventory
from .scan import _Sampled

_SYSTEM_SCHEMAS = {
    "information_schema",
    "pg_catalog",
    "pg_toast",
    "sys",
    "syscat",
    "sysibm",
    "sysstat",
    "mysql",
    "performance_schema",
}
_UNREAD = re.compile(
    r"blob|binary|bytea|image|json|xml|geometry|geography|array|struct|map|interval"
    r"|date|time|bool|uuid|\[\]$"
)
_FAMILIES = {
    "postgresql": "postgresql",
    "duckdb": "duckdb",
    "sqlite": "sqlite",
    "mysql": "mysql",
    "mariadb": "mysql",
    "ibm_db_sa": "db2",
    "db2": "db2",
}


class DatabaseInventory(Inventory):
    """An :class:`~credgate.Inventory` of a database, with the tables that
    could not be read (``failed``: ``schema.table`` -> error message) and
    those kept from an earlier run (``skipped``)."""

    def __init__(
        self, rows: Any = (), failed: dict[str, str] | None = None, skipped: Sequence[str] = ()
    ) -> None:
        super().__init__(rows)
        self.failed = dict(failed or {})
        self.skipped = list(skipped)

    def __str__(self) -> str:
        text = super().__str__()
        if self.skipped:
            text += f"\n{len(self.skipped)} table(s) unchanged since the last scan, kept."
        if self.failed:
            text += f"\nNot scanned ({len(self.failed)}): " + ", ".join(self.failed)
        return text


def inventory_database(
    connection: Any,
    source: str,
    path: str | os.PathLike[str] | None = None,
    schemas: Sequence[str] | None = None,
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
    views: bool = False,
    sample: int = 10000,
    min_rate: float = 0.0,
    detectors: Sequence[str] | None = None,
    max_age: float = 30,
    on_error: str = "warn",
) -> DatabaseInventory:
    """Record where PII is in every table of a database.

    Args:
        connection: A SQLAlchemy ``Engine`` or ``Connection``.
        source: Name of the data source for the inventory, e.g. ``"postgres:crm"``.
        path: Optional inventory file (CSV). Existing rows are read first;
            tables scanned within ``max_age`` days whose row count has not
            changed are kept rather than scanned again; the file is
            rewritten after each table, so an interrupted run can continue.
        schemas: Schemas to scan; default all except the database's own.
        include: Shell-style patterns for ``schema.table`` to scan (e.g.
            ``["crm.*"]``); default all.
        exclude: Patterns for ``schema.table`` to leave out.
        views: Also scan views (reading a view runs its query).
        sample: Maximum number of rows read per table.
        min_rate: As for :func:`credgate.scan_pii`.
        detectors: As for :func:`credgate.scan_pii`.
        max_age: Days after which a table is scanned again even if unchanged.
        on_error: ``"warn"`` (skip a table that cannot be read, and list it
            in ``failed``) or ``"stop"`` (raise).
    """
    import sqlalchemy

    if on_error not in ("warn", "stop"):
        raise ValueError('`on_error` must be "warn" or "stop".')
    engine = getattr(connection, "engine", connection)
    family = _FAMILIES.get(engine.dialect.name, "other")
    previous = _previous(path, source)
    now = datetime.now(UTC)
    rows: list[Any] = []
    failed: dict[str, str] = {}
    skipped: list[str] = []
    seen: list[str] = []

    with engine.connect() as conn:
        inspector = sqlalchemy.inspect(conn)
        for schema, table in _tables(inspector, schemas, include, exclude, views):
            name = f"{schema}.{table}"
            seen.append(name)
            try:
                n = _row_count(conn, family, schema, table)
                old = previous.get(name)
                if old and _unchanged(old, n, now, max_age):
                    rows.extend(old)
                    skipped.append(name)
                    continue
                columns = _columns(conn, inspector, family, schema, table)
                sql, read, method, fetch = sample_query(family, schema, table, n, columns, sample)
                values: dict[str, list[Any]] = {c: [] for c in read}
                if sql is not None:
                    result = conn.execute(sqlalchemy.text(sql))
                    got = result.fetchmany(fetch) if fetch else result.fetchall()
                    result.close()
                    for row in got:
                        for i, c in enumerate(read):
                            values[c].append(row[i])
                data = _Sampled({c: values.get(c, []) for c, _ in columns}, n, method)
                rows.extend(
                    pii_inventory(
                        data,
                        source=source,
                        table=name,
                        sample=sample,
                        min_rate=min_rate,
                        detectors=detectors,
                    )
                )
            except Exception as e:  # one table must not stop the inventory
                conn.rollback()
                if on_error == "stop":
                    raise
                failed[name] = str(e).splitlines()[0]
                warnings.warn(f"credgate: {name} not scanned: {failed[name]}", stacklevel=2)
                continue
            if path is not None:
                _write(path, rows, previous, seen)

    if path is not None:
        # Tables no longer in the database are dropped; those that failed
        # keep their earlier rows.
        _write(path, rows, {t: r for t, r in previous.items() if t in failed}, [])
    return DatabaseInventory(rows, failed=failed, skipped=skipped)


def sample_query(
    family: str,
    schema: str,
    table: str,
    n: int,
    columns: Sequence[tuple[str, str]],
    sample: int = 10000,
) -> tuple[str | None, list[str], str, int | None]:
    """The query that samples a table, the columns it reads, the sample
    method, and how many rows to read (``None``: all the query returns), as
    the spec's "Databases" rules say. ``columns`` are (name, type)."""
    read = [name for name, type_ in columns if not _UNREAD.search(type_.lower())]
    if not read:
        return None, [], "all", None
    q = _quote(family)
    sql = f"SELECT {', '.join(q(c) for c in read)} FROM {_table(family, schema, table)}"
    if n <= sample:
        return sql, read, "all", None
    p = _num(100 * max(0.000001, min(1.0, 1.2 * sample / n)))
    if family == "postgresql":
        return f"{sql} TABLESAMPLE SYSTEM ({p}) LIMIT {sample}", read, "tablesample", None
    if family == "db2":
        return (
            f"{sql} TABLESAMPLE SYSTEM ({p}) FETCH FIRST {sample} ROWS ONLY",
            read,
            "tablesample",
            None,
        )
    if family == "duckdb":
        # Not DuckDB's block sampling: its blocks hold about 2,000 rows, so a
        # small fraction of a medium-sized table is often no block at all.
        return f"{sql} USING SAMPLE {sample} ROWS (reservoir)", read, "reservoir", None
    if family in ("sqlite", "mysql"):
        return f"{sql} LIMIT {sample}", read, "first-rows", None
    return sql, read, "first-rows", sample


def _tables(
    inspector: Any,
    schemas: Sequence[str] | None,
    include: Sequence[str] | None,
    exclude: Sequence[str] | None,
    views: bool,
) -> list[tuple[str, str]]:
    if schemas is None:
        schemas = [
            s
            for s in inspector.get_schema_names()
            if s.lower() not in _SYSTEM_SCHEMAS
            and not s.lower().startswith(("pg_temp", "pg_toast_temp", "system.", "temp."))
        ]
    out = []
    for schema in sorted(schemas):
        names = list(inspector.get_table_names(schema=schema))
        if views:
            names += inspector.get_view_names(schema=schema)
        for table in sorted(set(names)):
            name = f"{schema}.{table}"
            if include and not any(fnmatch.fnmatchcase(name, p) for p in include):
                continue
            if exclude and any(fnmatch.fnmatchcase(name, p) for p in exclude):
                continue
            out.append((schema, table))
    return out


def _columns(conn: Any, inspector: Any, family: str, schema: str, table: str) -> list[Any]:
    """(name, type) of each column, from the driver, or from the standard
    information_schema when the driver cannot (duckdb-engine with DuckDB 2)."""
    import sqlalchemy

    try:
        return [(c["name"], str(c["type"])) for c in inspector.get_columns(table, schema)]
    except Exception:
        conn.rollback()
    catalog, _, name = schema.rpartition(".") if family == "duckdb" else ("", "", schema)
    query = (
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = :schema AND table_name = :table"
        + (" AND table_catalog = :catalog" if catalog else "")
        + " ORDER BY ordinal_position"
    )
    params = {"schema": name, "table": table, "catalog": catalog}
    return [(r[0], str(r[1])) for r in conn.execute(sqlalchemy.text(query), params)]


def _row_count(conn: Any, family: str, schema: str, table: str) -> int:
    import sqlalchemy

    if family == "postgresql":
        estimate = conn.execute(
            sqlalchemy.text(
                "SELECT c.reltuples FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace "
                "WHERE s.nspname = :schema AND c.relname = :table"
            ),
            {"schema": schema, "table": table},
        ).scalar()
        if estimate is not None and estimate >= 0:
            return int(estimate)
    count = f"SELECT COUNT(*) FROM {_table(family, schema, table)}"
    return int(conn.execute(sqlalchemy.text(count)).scalar())


def _quote(family: str) -> Any:
    if family == "mysql":
        return lambda x: "`" + x.replace("`", "``") + "`"
    return lambda x: '"' + x.replace('"', '""') + '"'


def _table(family: str, schema: str, table: str) -> str:
    """The quoted table name. DuckDB's driver names schemas `catalog.schema`."""
    q = _quote(family)
    parts = schema.split(".", 1) if family == "duckdb" else [schema]
    return ".".join(q(x) for x in [*parts, table])


def _previous(path: str | os.PathLike[str] | None, source: str) -> dict[str, list[Any]]:
    if path is None or not Path(path).exists():
        return {}
    out: dict[str, list[Any]] = {}
    for row in read_inventory(path):
        if row.source == source:
            out.setdefault(row.table, []).append(row)
    return out


def _unchanged(rows: list[Any], n: int, now: datetime, max_age: float) -> bool:
    row = rows[0]
    scanned = datetime.strptime(row.scanned_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return row.n_rows is not None and row.n_rows == n and now - scanned <= timedelta(days=max_age)


def _write(
    path: str | os.PathLike[str], rows: list[Any], previous: dict[str, list[Any]], seen: list[str]
) -> None:
    """Write the rows so far, keeping earlier rows of tables not reached yet."""
    pending = [r for t, rs in previous.items() if t not in seen for r in rs]
    tmp = Path(f"{path}.tmp")
    Inventory([*rows, *pending]).write(tmp)
    os.replace(tmp, path)


def _num(x: float) -> str:
    return f"{x:.6f}".rstrip("0").rstrip(".")
