"""pandas, Polars, Arrow and DuckDB integrations. Each test skips when its
library is not installed."""

from __future__ import annotations

import pytest

import credgate

NOTES = ["PAN ABCPE1234F", None, "Name: Priya Nair", "nothing here"]
REDACTED = ["PAN [PAN]", None, "Name: [PERSON_NAME]", "nothing here"]


def _scan_key(report):
    return [
        (f.column, f.type, f.n_sampled, f.n_matched, f.n_full, f.rate, f.mean_confidence, f.example)
        for f in report
    ]


@pytest.fixture(scope="module")
def table_columns():
    recs = credgate.synth_indian_pii(1200, seed=5)
    return {
        "cust_pan": [r["pan"] for r in recs],
        "mobile": [int(r["mobile"]) if i % 7 else None for i, r in enumerate(recs)],
        "notes": [
            f"Shri {r['name']}, PAN {r['pan']}" if i % 4 == 0 else f"Customer {r['name']} called"
            for i, r in enumerate(recs)
        ],
        "amount": [i + 0.5 for i in range(1200)],
    }


def test_plain_lists_keep_non_text_values():
    assert credgate.redact(["PAN ABCPE1234F", None, 42]) == ["PAN [PAN]", None, 42]


# --- pandas ---------------------------------------------------------------


def test_pandas_series_keeps_index_name_and_missing():
    pd = pytest.importorskip("pandas")
    s = pd.Series(NOTES, index=[10, 11, 12, 13], name="notes")
    out = credgate.redact(s)
    assert isinstance(out, pd.Series)
    assert out.index.tolist() == [10, 11, 12, 13]
    assert out.name == "notes"
    assert out.isna().tolist() == [False, True, False, False]
    assert out.dropna().tolist() == [r for r in REDACTED if r is not None]
    tokens = credgate.tokenise(s, credgate.Vault())
    assert tokens[10] == "PAN [PAN_1]"
    assert [s.doc for s in credgate.detect_pii(s)] == [0, 2]


def test_pandas_categorical_comes_back_as_text():
    pd = pytest.importorskip("pandas")
    s = pd.Series(["PAN ABCPE1234F", "PAN ABCPE1234F", "ok"], dtype="category")
    assert credgate.redact(s).tolist() == ["PAN [PAN]", "PAN [PAN]", "ok"]


# --- Polars ---------------------------------------------------------------


def test_polars_expression_namespace():
    pl = pytest.importorskip("polars")
    import credgate.polars

    df = pl.DataFrame({"id": [1, 2, 3, 4], "notes": NOTES})
    out = df.with_columns(pl.col("notes").credgate.redact(), has=pl.col("notes").credgate.has_pii())
    assert out["notes"].to_list() == REDACTED
    assert out["has"].to_list() == [True, None, True, False]
    lazy = df.lazy().select(pl.col("notes").credgate.redact(min_confidence=0.5)).collect()
    assert lazy["notes"].to_list() == REDACTED
    assert df["notes"].credgate.redact().to_list() == REDACTED
    assert credgate.redact(df["notes"]).to_list() == REDACTED


def test_polars_scan_matches_in_memory(table_columns, tmp_path):
    pl = pytest.importorskip("polars")
    ref = _scan_key(credgate.scan_pii(table_columns, sample=500))
    df = pl.DataFrame(table_columns)
    assert _scan_key(credgate.scan_pii(df, sample=500)) == ref
    path = tmp_path / "t.parquet"
    df.write_parquet(path, row_group_size=100)
    assert _scan_key(credgate.scan_pii(pl.scan_parquet(path), sample=500)) == ref


# --- Arrow ----------------------------------------------------------------


def test_arrow_arrays_tables_and_parquet(tmp_path):
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    import credgate.arrow

    assert credgate.redact(pa.array(NOTES)).to_pylist() == REDACTED
    assert credgate.redact(pa.chunked_array([NOTES[:2], NOTES[2:]])).to_pylist() == REDACTED

    table = pa.table({"id": [1, 2, 3, 4], "notes": NOTES, "pan": ["ABCPE1234F", "x", None, "y"]})
    out = credgate.arrow.redact_table(table, columns=["notes"])
    assert out.schema == table.schema
    assert out.column("notes").to_pylist() == REDACTED
    assert out.column("pan").to_pylist() == ["ABCPE1234F", "x", None, "y"]
    assert credgate.arrow.redact_table(table).column("pan").to_pylist() == ["[PAN]", "x", None, "y"]
    with pytest.raises(KeyError, match="nope"):
        credgate.arrow.redact_table(table, columns=["nope"])

    src, dst = tmp_path / "in.parquet", tmp_path / "out.parquet"
    pq.write_table(table, src)
    assert credgate.arrow.redact_parquet(src, dst, columns=["notes"], batch_size=1) == 4
    assert pq.read_table(dst).column("notes").to_pylist() == REDACTED
    with pytest.raises(ValueError, match="differ"):
        credgate.arrow.redact_parquet(src, src)


def test_arrow_scan_matches_in_memory(table_columns, tmp_path):
    pa = pytest.importorskip("pyarrow")
    ds = pytest.importorskip("pyarrow.dataset")
    pq = pytest.importorskip("pyarrow.parquet")
    ref = _scan_key(credgate.scan_pii(table_columns, sample=500))
    table = pa.table(table_columns)
    chunked = pa.Table.from_batches(table.to_batches(max_chunksize=111))
    assert _scan_key(credgate.scan_pii(chunked, sample=500)) == ref
    path = tmp_path / "t.parquet"
    pq.write_table(table, path, row_group_size=100)
    assert _scan_key(credgate.scan_pii(ds.dataset(path), sample=500)) == ref


def test_cli_parquet_redact_and_scan(tmp_path, capsys):
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    from credgate.cli import main

    src, dst = tmp_path / "in.parquet", tmp_path / "out.parquet"
    pq.write_table(pa.table({"notes": NOTES, "pan": ["ABCPE1234F"] * 4}), src)
    assert main(["redact", "--parquet", str(src), "--column", "notes", "-o", str(dst)]) == 0
    assert pq.read_table(dst).column("notes").to_pylist() == REDACTED
    assert main(["redact", "--parquet", str(src)]) == 2
    capsys.readouterr()
    assert main(["scan", str(src), "--json"]) == 0
    assert '"column": "pan"' in capsys.readouterr().out


# --- DuckDB ---------------------------------------------------------------


def test_duckdb_functions(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    pytest.importorskip("pyarrow")
    import credgate.duckdb

    con = duckdb.connect()
    credgate.duckdb.register(con)
    con.execute(
        "CREATE TABLE t AS SELECT * FROM (VALUES (1, 'PAN ABCPE1234F'), "
        "(2, NULL), (3, 'Name: Priya Nair'), (4, 'nothing here')) v(id, notes)"
    )
    rows = con.sql("SELECT cg_redact(notes), cg_has_pii(notes) FROM t ORDER BY id").fetchall()
    assert rows == [(r, h) for r, h in zip(REDACTED, [True, None, True, False], strict=True)]
    credgate.duckdb.register(con, min_confidence=0.5, prefix="strict_")
    assert con.execute("SELECT strict_redact('order no 878245671885')").fetchone()[0] == (
        "order no 878245671885"
    )


def test_duckdb_scan_matches_in_memory(table_columns, tmp_path):
    duckdb = pytest.importorskip("duckdb")
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    ref = _scan_key(credgate.scan_pii(table_columns, sample=500))
    path = tmp_path / "t.parquet"
    pq.write_table(pa.table(table_columns), path, row_group_size=100)
    rel = duckdb.connect().sql(f"FROM '{path}'")
    assert _scan_key(credgate.scan_pii(rel, sample=500)) == ref
