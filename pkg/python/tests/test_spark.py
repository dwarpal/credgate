"""PySpark: sampling in the cluster (the spec's "Spark tables"). Needs
pyspark and Java; skipped otherwise."""

from __future__ import annotations

import pytest

import credgate

pyspark = pytest.importorskip("pyspark")


@pytest.fixture(scope="module")
def spark():
    from pyspark.sql import SparkSession

    try:
        session = (
            SparkSession.builder.master("local[1]")
            .appName("credgate-tests")
            .config("spark.ui.enabled", "false")
            .config("spark.driver.host", "127.0.0.1")
            .config("spark.sql.shuffle.partitions", "1")
            .getOrCreate()
        )
    except Exception as e:  # no Java
        pytest.skip(f"Spark cannot start: {e}")
    yield session
    session.stop()


TABLE = {
    "cust_pan": ["ABCPE1234F", "AAACR5055K", "XYZPQ9876R", None],
    "notes": ["Called, Aadhaar 542229371182", "no issues", "mobile 9876543210", "ok"],
}


def _rows(inv):
    drop = ("scanned_at", "credgate")
    return [{k: v for k, v in r.items() if k not in drop} for r in inv.to_records()]


def test_small_table_matches_in_memory(spark):
    df = spark.createDataFrame(list(zip(*TABLE.values(), strict=True)), list(TABLE))
    got = credgate.pii_inventory(df, source="hive", table="crm.customers")
    expected = credgate.pii_inventory(TABLE, source="hive", table="crm.customers")
    assert _rows(got) == _rows(expected)
    assert {r.sample_method for r in got} == {"all"}
    assert credgate.scan_pii(df).to_records() == credgate.scan_pii(TABLE).to_records()


def test_large_table_is_sampled_in_the_cluster(spark):
    pans = [r["pan"] for r in credgate.synth_indian_pii(3000, seed=1)]
    df = spark.createDataFrame([(p, "ok") for p in pans], ["pan", "status"])
    inv = credgate.pii_inventory(df, source="hive", table="t", sample=500)
    assert {r.sample_method for r in inv} == {"spark-sample"}
    assert {r.n_rows for r in inv} == {3000}
    pan = next(r for r in inv if r.type == "pan")
    assert 0 < pan.n_sampled <= 500
    assert pan.rate == 1.0
    again = credgate.pii_inventory(df, source="hive", table="t", sample=500)
    assert _rows(again) == _rows(inv)  # same seed, same sample


def test_long_identifiers_keep_every_digit(spark):
    from pyspark.sql import types as T

    cards = [int(r["card"]) for r in credgate.synth_indian_pii(5, seed=2)]
    schema = T.StructType([T.StructField("card_no", T.LongType())])
    df = spark.createDataFrame([(c,) for c in cards], schema)
    found = credgate.scan_pii(df)
    assert [(f.type, f.n_full) for f in found] == [("card", 5)]


def test_nested_columns_are_recorded_but_not_read(spark):
    from pyspark.sql import types as T

    schema = T.StructType(
        [
            T.StructField("pan", T.StringType()),
            T.StructField("tags", T.ArrayType(T.StringType())),
        ]
    )
    df = spark.createDataFrame([("ABCPE1234F", ["ABCPE1234F"])], schema)
    inv = credgate.pii_inventory(df, source="hive", table="t")
    tags = [r for r in inv if r.column == "tags"]
    assert [(r.type, r.n_sampled) for r in tags] == [(None, 0)]
