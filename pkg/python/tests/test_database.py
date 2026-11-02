"""Whole-database inventories (the spec's "Databases") on SQLite, and on
DuckDB where its SQLAlchemy driver is installed. Postgres runs in the R
integration tests."""

from __future__ import annotations

import pytest

import credgate

sqlalchemy = pytest.importorskip("sqlalchemy")
from credgate.database import inventory_database  # noqa: E402

PANS = ["ABCPE1234F", "AAACR5055K", "XYZPQ9876R", "BNZPM2501F"]


def _sqlite(tmp_path, rows=40):
    engine = sqlalchemy.create_engine(f"sqlite:///{tmp_path / 'crm.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE customers "
            "(pan TEXT, account_no INTEGER, notes TEXT, dob DATE, photo BLOB)"
        )
        conn.exec_driver_sql("CREATE TABLE calls (note TEXT)")
        for i in range(rows):
            conn.exec_driver_sql(
                "INSERT INTO customers VALUES (?, ?, ?, '1990-01-01', x'00')",
                (PANS[i % 4], 50100012345678 + i, "Aadhaar 542229371182" if i % 2 else "ok"),
            )
        conn.exec_driver_sql("INSERT INTO calls VALUES ('mobile 9876543210')")
    return engine


def _rows(inv):
    return [
        {k: v for k, v in r.items() if k not in ("scanned_at", "credgate")}
        for r in inv.to_records()
    ]


def test_every_table_matches_the_in_memory_inventory(tmp_path):
    engine = _sqlite(tmp_path)
    inv = inventory_database(engine, source="sqlite:crm")
    assert sorted({r.table for r in inv}) == ["main.calls", "main.customers"]
    with engine.connect() as conn:
        data = conn.exec_driver_sql("SELECT pan, account_no, notes FROM customers").fetchall()
    expected = credgate.pii_inventory(
        {"pan": [r[0] for r in data], "account_no": [r[1] for r in data],
         "notes": [r[2] for r in data], "dob": [], "photo": []},
        source="sqlite:crm",
        table="main.customers",
    )  # fmt: skip
    assert [r for r in _rows(inv) if r["table"] == "main.customers"] == _rows(expected)
    assert {r.n_sampled for r in inv if r.column in ("dob", "photo")} == {0}
    assert any(r.table == "main.calls" and r.type == "mobile_in" for r in inv)


def test_large_tables_read_only_the_sample(tmp_path):
    inv = inventory_database(_sqlite(tmp_path, rows=300), source="sqlite:crm", sample=50)
    customers = [r for r in inv if r.table == "main.customers"]
    assert {r.sample_method for r in customers} == {"first-rows"}
    assert {r.n_rows for r in customers} == {300}
    assert max(r.n_sampled for r in customers) == 50


def test_resume_and_change_detection(tmp_path):
    engine = _sqlite(tmp_path)
    path = tmp_path / "inventory.csv"
    first = inventory_database(engine, source="sqlite:crm", path=path)
    assert first.skipped == []
    assert credgate.read_inventory(path) == first

    again = inventory_database(engine, source="sqlite:crm", path=path)
    assert again.skipped == ["main.calls", "main.customers"]
    assert _rows(again) == _rows(first)

    with engine.begin() as conn:
        conn.exec_driver_sql("INSERT INTO calls VALUES ('PAN ABCPE1234F')")
    changed = inventory_database(engine, source="sqlite:crm", path=path)
    assert changed.skipped == ["main.customers"]
    assert any(r.table == "main.calls" and r.type == "pan" for r in changed)

    stale = inventory_database(engine, source="sqlite:crm", path=path, max_age=0)
    assert stale.skipped == []


def test_patterns_errors_and_dropped_tables(tmp_path):
    engine = _sqlite(tmp_path)
    path = tmp_path / "inventory.csv"
    inv = inventory_database(engine, source="sqlite:crm", include=["main.cust*"])
    assert {r.table for r in inv} == {"main.customers"}
    inv = inventory_database(engine, source="sqlite:crm", exclude=["*.customers"], path=path)
    assert {r.table for r in inv} == {"main.calls"}

    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE VIEW broken AS SELECT missing FROM nowhere")
        conn.exec_driver_sql("DROP TABLE calls")
    with pytest.warns(UserWarning, match="main.broken not scanned"):
        inv = inventory_database(engine, source="sqlite:crm", views=True, path=path)
    assert list(inv.failed) == ["main.broken"]
    assert "Not scanned (1): main.broken" in str(inv)
    assert "main.calls" not in {r.table for r in credgate.read_inventory(path)}
    with pytest.raises(Exception, match="nowhere"):
        inventory_database(engine, source="sqlite:crm", views=True, on_error="stop")


def test_duckdb_samples_in_the_database(tmp_path):
    pytest.importorskip("duckdb_engine")
    engine = sqlalchemy.create_engine(f"duckdb:///{tmp_path / 'warehouse.duckdb'}")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE SCHEMA crm")
        conn.exec_driver_sql(
            "CREATE TABLE crm.calls AS SELECT 'PAN ABCPE1234F, mobile 9876543210' AS note "
            "FROM range(200000)"
        )
    inv = inventory_database(engine, source="duckdb", sample=1000)
    # DuckDB's driver names schemas catalog.schema (the database file's name).
    rows = [r for r in inv if r.table == "warehouse.crm.calls"]
    assert {r.sample_method for r in rows} == {"reservoir"}
    assert {r.n_rows for r in rows} == {200000}
    assert {r.type for r in rows} == {"pan", "mobile_in"}
    assert {r.n_sampled for r in rows} == {1000}  # exactly `sample` rows
