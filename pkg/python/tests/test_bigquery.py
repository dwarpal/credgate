"""BigQuery against the open-source BigQuery emulator (goccy/bigquery-emulator),
started on a free local port. Needs google-cloud-bigquery and the
`bigquery-emulator` program; skipped otherwise. The emulator has no
TABLESAMPLE, so block sampling is covered by the query conformance cases."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
import urllib.request

import pytest

import credgate

bigquery = pytest.importorskip("google.cloud.bigquery")
from credgate import bigquery as cgbq  # noqa: E402

PANS = ["ABCPE1234F", "AAACR5055K", "XYZPQ9876R", "BNZPM2501F", "CQTPS7733L"]
ROWS = [
    {
        "pan": PANS[i % 5],
        "acct": 50100012345678 + i,
        "notes": "Called, Aadhaar 542229371182" if i % 2 else "no issues",
        "tags": ["vip"],
        "addr": {"city": "Pune"},
    }
    for i in range(40)
]


@pytest.fixture(scope="module")
def client():
    program = shutil.which("bigquery-emulator")
    if program is None:
        pytest.skip("bigquery-emulator is not installed")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        [
            program,
            "--project=test",
            "--dataset=crm",
            "--host=127.0.0.1",
            f"--port={port}",
            "--grpc-port=0",
            "--log-level=error",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{url}/bigquery/v2/projects/test/datasets", timeout=1)
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.skip("the BigQuery emulator did not start")
    from google.api_core.client_options import ClientOptions
    from google.auth.credentials import AnonymousCredentials

    c = bigquery.Client(
        project="test",
        credentials=AnonymousCredentials(),
        client_options=ClientOptions(api_endpoint=url),
    )
    schema = [
        bigquery.SchemaField("pan", "STRING"),
        bigquery.SchemaField("acct", "INT64"),
        bigquery.SchemaField("notes", "STRING"),
        bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
        bigquery.SchemaField("addr", "RECORD", fields=[bigquery.SchemaField("city", "STRING")]),
    ]
    table = c.create_table(bigquery.Table("test.crm.customers", schema=schema))
    assert c.insert_rows(table, ROWS) == []
    other = c.create_table(
        bigquery.Table("test.crm.calls", schema=[bigquery.SchemaField("note", "STRING")])
    )
    assert c.insert_rows(other, [{"note": "mobile 9876543210"}]) == []
    yield c
    proc.terminate()
    proc.wait(timeout=10)


def _rows(inv):
    drop = ("scanned_at", "credgate", "source", "sample_method")
    return [{k: v for k, v in r.items() if k not in drop} for r in inv.to_records()]


def test_small_table_matches_in_memory(client):
    inv = cgbq.pii_inventory(client, "test.crm.customers")
    in_memory = credgate.pii_inventory(
        {k: [r[k] for r in ROWS] for k in ("pan", "acct", "notes")} | {"tags": [], "addr": []},
        source="bigquery:test",
        table="crm.customers",
    )
    assert _rows(inv) == _rows(in_memory)
    assert {r.source for r in inv} == {"bigquery:test"}
    assert {r.sample_method for r in inv} == {"all"}
    assert [(r.column, r.n_sampled) for r in inv if r.column in ("tags", "addr")] == [
        ("tags", 0),
        ("addr", 0),
    ]
    found = [(f.column, f.type) for f in cgbq.scan_pii(client, "test.crm.customers")]
    assert found == [("pan", "pan"), ("acct", "bank_account"), ("notes", "aadhaar")]


def test_large_table_is_sampled_by_bigquery(client):
    inv = cgbq.pii_inventory(client, "test.crm.customers", sample=10, sampling="rand")
    assert {r.sample_method for r in inv} == {"bigquery-rand"}
    assert {r.n_rows for r in inv} == {40}
    # The emulator evaluates RAND() once per query, not per row, so its
    # sample is all rows or none; BigQuery samples rows. The LIMIT holds.
    assert all(r.n_sampled <= 10 for r in inv)


def test_cost_limit_stops_before_running(client):
    with pytest.raises(cgbq.CostLimitError, match="nothing was run"):
        cgbq.scan_pii(client, "test.crm.customers", max_bytes=1)


def test_whole_dataset(client):
    inv = cgbq.inventory_dataset(client, "test.crm")
    assert sorted({r.table for r in inv}) == ["crm.calls", "crm.customers"]
    assert any(r.table == "crm.calls" and r.type == "mobile_in" for r in inv)


class _FakeClient:
    """Records the queries and job settings that would reach BigQuery."""

    def __init__(self, n, kind="TABLE"):
        self.n, self.kind, self.jobs = n, kind, []

    def get_table(self, table):
        field = type("Field", (), {"name": "pan", "field_type": "STRING", "mode": "NULLABLE"})
        return type(
            "Table",
            (),
            {
                "project": "p",
                "dataset_id": "d",
                "table_id": "t",
                "num_rows": self.n,
                "table_type": self.kind,
                "schema": [field],
            },
        )

    def query(self, sql, job_config):
        self.jobs.append((sql, job_config.dry_run, job_config.maximum_bytes_billed))
        rows = [("ABCPE1234F",)] * 3
        return type("Job", (), {"total_bytes_processed": 1000, "result": lambda self: rows})()


@pytest.mark.parametrize(("kind", "limit"), [("TABLE", None), ("VIEW", 10**9)])
def test_bigquery_limit_is_not_sent_with_tablesample(kind, limit):
    # BigQuery checks maximumBytesBilled against the whole table for
    # TABLESAMPLE, though it bills only the sampled blocks.
    client = _FakeClient(n=10**6, kind=kind)
    cgbq.scan_pii(client, "p.d.t", sample=100)
    dry, run = client.jobs
    assert dry[1] is True
    assert run[1] is not True
    assert run[2] == limit
    assert ("TABLESAMPLE" in run[0]) == (kind == "TABLE")
