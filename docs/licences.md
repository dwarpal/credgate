# Licences

credgate is open source under the **Apache License 2.0**, which allows
commercial use, modification and redistribution. This page lists the
licences of everything credgate uses, so that legal and procurement teams
can check them in one place. It describes the licences as published; it is
not legal advice.

**In short:** credgate and everything it needs in Python are under
permissive licences (Apache-2.0, MIT, BSD). The R package's required
dependencies are permissive too; a few optional R packages, and R itself,
are under the GPL or LGPL - see [R](#r) below for what that means in
practice.

## credgate

| | Licence |
|---|---|
| The R package, the Python package, the specification | Apache-2.0 |
| Indian district and town names (the `india_places` list, for addresses) | Government Open Data License - India: derived from India Post's All India Pincode Directory (data.gov.in); attribution in the `NOTICE` file |

Apache-2.0 asks that you keep the `LICENSE` and `NOTICE` files when you
redistribute credgate, and mark files you change. Both packages ship them.

## Python

Installed with `pip install credgate`:

| Package | Licence | Used for |
|---|---|---|
| regex | Apache-2.0 (with the CNRI Python licence for parts) | detection |
| PyYAML | MIT | policies, detector files |

Extras, installed only when you ask for them (`pip install 'credgate[...]'`):

| Extra | Packages | Licences |
|---|---|---|
| `vault` | PyNaCl | Apache-2.0 |
| `server` (proxy on uvicorn) | uvicorn, httptools, uvloop | BSD-3, MIT, MIT |
| `editor` (policy editor) | Shiny for Python, htmltools, shinychat, narwhals, Starlette, uvicorn, websockets and about 20 small packages | MIT, BSD-2/3, Apache-2.0, Python licence |
| `arrow` | pyarrow | Apache-2.0 |
| `polars` | polars | MIT |
| `duckdb` | duckdb, pyarrow, numpy | MIT, Apache-2.0, BSD-3 |
| `bigquery` | google-cloud-bigquery | Apache-2.0 |
| `database` | SQLAlchemy | MIT |
| `spark` | pyspark | Apache-2.0 |

The policy editor also sends these files to the browser, inside Shiny for
Python:

| | Licence |
|---|---|
| Bootstrap, jQuery, jQuery UI, ion.rangeSlider, strftime, RequireJS | MIT |
| selectize, bootstrap-datepicker | Apache-2.0 |
| highlight.js | BSD-3 |
| The Open Sans font | SIL Open Font License 1.1 (may be used in any app, commercial included; only selling the font on its own is not allowed) |

There is no GPL, LGPL or AGPL code anywhere in the Python package or its
extras.

## R

Required (`Imports`), installed with credgate:

| Package | Licence |
|---|---|
| cli, jsonlite, rlang | MIT |
| yaml | BSD-3 |
| stringi | BSD-3, with the ICU (Unicode) licence for the ICU library it includes |

Optional (`Suggests`), used only by the features that need them:

| Package | Licence | Needed for |
|---|---|---|
| shiny, bslib | MIT | the policy editor |
| **htmltools** | **GPL (>= 2)** | the policy editor (shiny depends on it) |
| openssl, sodium, askpass | MIT | keyed tokens, saved vaults, the audit log's hashes |
| arrow, sparklyr | Apache-2.0 | Arrow and Parquet; Spark |
| duckdb, dplyr, dbplyr, bigrquery | MIT | DuckDB, databases, BigQuery |
| **DBI** | **LGPL (>= 2.1)** | databases (`redact_query()`, `inventory_database()`) |
| **RSQLite** | **LGPL (>= 2.1)** | tests and examples only |
| **knitr**, **rmarkdown** | **GPL** | building the vignettes only |
| testthat, withr | MIT | tests |

**What this means.** R itself is GPL-licensed, and so are some of the most
widely used R packages. credgate does not include, copy or modify their
code; it calls them, when you have installed them, as every R package does.
The GPL and LGPL do not restrict *using* software, inside a company or
commercially; their conditions apply when you *distribute* the software
(for example, shipping a product that bundles a modified copy). Running
credgate on your own servers, with these packages installed from CRAN, is
use, not distribution. If you need a stack with no copyleft at all - some
procurement rules ask for that - the Python package, including its policy
editor, is entirely permissive. Ask your legal team if you are unsure.

## Running it for a team

The [deployment guide](deployment.md) uses only permissive software in
front of credgate: nginx (BSD-2), OAuth2 Proxy (MIT), Keycloak and Caddy
(Apache-2.0). It runs the R editor with `shiny::runApp()` rather than the
open-source Shiny Server, which is AGPL-licensed.

## Benchmark data

The public datasets in the [benchmark comparison](blog/posts/indian-pii-benchmarks.md)
are not shipped with credgate: the benchmark scripts download them when you
run them. The Ylemis India-PII Benchmark is CC0; IndiaPII-Bench is CC BY
4.0. credgate's own benchmark corpus is synthetic and Apache-2.0.

## Adding a dependency

credgate accepts only dependencies under permissive licences (Apache-2.0,
MIT, BSD and the like) that are maintained and used in production. To check
the licences installed in your own environment: in Python, `pip-licenses`
(itself MIT) or `pip show <package>`; in R,
`packageDescription("<package>")$License`.
