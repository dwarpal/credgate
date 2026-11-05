"""Redacting a query's result into a table (R's redact_query()), on SQLite,
and on DuckDB where its SQLAlchemy driver is installed."""

from __future__ import annotations

import pytest

import credgate

sqlalchemy = pytest.importorskip("sqlalchemy")
from credgate.database import redact_query  # noqa: E402

NOTES = ["Called, PAN ABCPE1234F", "no PII", None, "mobile 9876543210"]


def _calls(engine, n=4):
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE calls (id INTEGER, notes TEXT, pan TEXT)")
        for i in range(n):
            conn.exec_driver_sql(
                "INSERT INTO calls VALUES (?, ?, ?)", (i + 1, NOTES[i % 4], "ABCPE1234F")
            )


def _redacted(n=4):
    out = credgate.redact([v or "" for v in NOTES])
    return [None if NOTES[i % 4] is None else out[i % 4] for i in range(n)]


def _rows(engine, sql):
    with engine.connect() as conn:
        return [tuple(r) for r in conn.exec_driver_sql(sql)]


def test_one_connection_spills_and_writes_in_one_transaction(tmp_path):
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'crm.db'}")
    _calls(engine, n=2500)
    n = redact_query(engine, "SELECT * FROM calls ORDER BY id", "one_con", chunk_size=1000)
    assert n == 2500
    got = _rows(engine, "SELECT notes FROM one_con ORDER BY id")
    assert [r[0] for r in got] == _redacted(2500)


def test_columns_append_and_errors(tmp_path):
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'crm.db'}")
    _calls(engine)
    n = redact_query(
        engine, "SELECT * FROM calls ORDER BY id", "safe", columns=["notes"], chunk_size=3
    )
    assert n == 4
    got = _rows(engine, "SELECT id, notes, pan FROM safe ORDER BY id")
    assert [r[1] for r in got] == _redacted()
    assert [r[2] for r in got] == ["ABCPE1234F"] * 4  # not chosen: kept
    assert [r[0] for r in got] == [1, 2, 3, 4]  # numbers stay numbers
    with pytest.raises(ValueError, match="append=True"):
        redact_query(engine, "SELECT * FROM calls", "safe")
    # every text column by default, added to the table
    redact_query(engine, "SELECT * FROM calls ORDER BY id", "safe", append=True)
    pans = sorted(r[0] for r in _rows(engine, "SELECT pan FROM safe"))
    assert pans == ["ABCPE1234F"] * 4 + ["[PAN]"] * 4
    with pytest.raises(ValueError, match="Unknown column"):
        redact_query(engine, "SELECT * FROM calls", "other", columns=["nope"])
    redact_query(engine, "SELECT * FROM calls WHERE id > 99", "empty")
    assert sqlalchemy.inspect(engine).has_table("empty")


def test_a_second_connection_writes_as_it_reads(tmp_path):
    db = tmp_path / "crm.db"
    engine = sqlalchemy.create_engine(f"sqlite:///{db}")
    _calls(engine)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode = WAL")
    writer = sqlalchemy.create_engine(f"sqlite:///{db}")
    with engine.connect() as reader, writer.connect() as out:
        n = redact_query(reader, "SELECT * FROM calls ORDER BY id", "safe", to_connection=out)
    assert n == 4
    assert [r[0] for r in _rows(engine, "SELECT notes FROM safe ORDER BY id")] == _redacted()


def test_a_callers_transaction_is_left_to_the_caller(tmp_path):
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'crm.db'}")
    _calls(engine)
    with engine.connect() as conn, conn.begin() as tx:
        redact_query(conn, "SELECT * FROM calls", "safe")
        tx.rollback()
    # SQLite's driver commits CREATE TABLE at once; the rows are rolled back.
    if sqlalchemy.inspect(engine).has_table("safe"):
        assert _rows(engine, "SELECT COUNT(*) FROM safe") == [(0,)]


def test_duckdb_reads_files_directly(tmp_path):
    pytest.importorskip("duckdb_engine")
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    src = tmp_path / "calls.parquet"
    pq.write_table(pa.table({"id": [1, 2], "notes": ["PAN ABCPE1234F", "no PII"]}), src)
    engine = sqlalchemy.create_engine(f"duckdb:///{tmp_path / 'w.duckdb'}")
    assert redact_query(engine, f"SELECT * FROM '{src}' ORDER BY id", "calls_safe") == 2
    assert [r[0] for r in _rows(engine, "SELECT notes FROM calls_safe ORDER BY id")] == [
        "PAN [PAN]",
        "no PII",
    ]
