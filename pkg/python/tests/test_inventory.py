from __future__ import annotations

import re

import pytest

import credgate

TABLE = {
    "cust_pan": ["ABCPE1234F", "AAACR5055K", "XYZPQ9876R"],
    "notes": ["Called, Aadhaar 542229371182", "no issues", "mobile 9876543210"],
    "balance": [1520.5, 99.75, 0.25],
}


def test_records_every_column_and_no_values(tmp_path):
    inv = credgate.pii_inventory(TABLE, source="crm", table="customers")
    assert list(dict.fromkeys(r.column for r in inv)) == ["cust_pan", "notes", "balance"]
    text = inv.write(tmp_path / "inv.csv").read_text(encoding="utf-8")
    for value in ("ABCPE1234F", "1234F", "542229371182", "1182", "9876543210", "3210"):
        assert value not in text
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", inv[0].scanned_at)
    assert inv[0].credgate == f"python/{credgate.__version__}"


def test_combine_write_and_read_back(tmp_path):
    inv = credgate.pii_inventory(TABLE, source="crm", table="customers")
    inv += credgate.pii_inventory({"x": ["ok"]}, source="lake", table="a,b")
    assert isinstance(inv, credgate.Inventory)
    back = credgate.read_inventory(inv.write(tmp_path / "inv.csv"))
    assert back == inv
    assert "Inventory of 2 table(s)" in str(inv)
    assert "crm: customers - 3 column(s) scanned, PII in 2" in str(inv)


def test_row_count_unknown_for_lazy_tables():
    pl = pytest.importorskip("polars")
    inv = credgate.pii_inventory(pl.LazyFrame(TABLE), source="crm", table="customers")
    assert {r.n_rows for r in inv} == {None}
    inv = credgate.pii_inventory(pl.DataFrame(TABLE), source="crm", table="customers")
    assert {r.n_rows for r in inv} == {3}


def test_requires_source_and_table():
    with pytest.raises(ValueError, match="source"):
        credgate.pii_inventory(TABLE, source="", table="customers")
    with pytest.raises(ValueError, match="table"):
        credgate.pii_inventory(TABLE, source="crm", table=None)


def test_read_rejects_other_files(tmp_path):
    path = tmp_path / "other.csv"
    path.write_text("a,b\n1,2\n")
    with pytest.raises(ValueError, match="not a credgate inventory"):
        credgate.read_inventory(path)
    good = credgate.pii_inventory(TABLE, source="crm", table="t").write(tmp_path / "inv.csv")
    lines = good.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[1].replace(",3,", ",three,", 1)]) + "\n")
    with pytest.raises(ValueError, match="line 2"):
        credgate.read_inventory(path)
