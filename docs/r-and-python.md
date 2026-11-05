# R and Python

credgate is one tool in two packages. Both read the same
[specification](spec.md), and a shared set of conformance cases - run by
both test suites on every change - holds them to the same results. This
page lists what is the same, how the names map, and the few places they
differ, and why.

## The same in both

Given the same input, R and Python give the same output, and each reads
what the other writes:

- **Detection**: the same matches, confidence scores and reasons, and the
  same explanations of what was not reported.
- **Redaction and tokens**: the same placeholders and tokens; keyed tokens
  agree across languages, and a vault saved by one opens in the other.
- **Column scans and PII inventories**: the same findings, samples and
  inventory files.
- **Policies, policy tests and the audit log**: the same decisions, test
  results and audit records.
- **The policy editor**: the same app, tabs and roles, on the same files. A
  policy saved by either editor is written byte for byte the same, with the
  same change log.
- **Custom detectors, proxy keys, the users file and the access log**: the
  same file formats, read and written the same way.

## Names

Each language follows its own conventions: R uses functions with a `cg_`
prefix where a bare name would clash, Python uses classes and methods.

| | R | Python |
|---|---|---|
| Detect | `detect_pii()` | `credgate.detect_pii()` |
| Preview, redact | `preview()`, `redact()` | `credgate.preview()`, `credgate.redact()` |
| Tokenise, restore | `tokenise()`, `restore()` | `credgate.tokenise()`, `credgate.restore()` |
| Vault | `cg_vault()`, `vault_save()`, `vault_open()`, `vault_merge()` | `credgate.Vault`, `.save()`, `Vault.open()`, `.merge()` |
| Keyed tokens | `cg_new_token_key()`, `cg_key_fingerprint()` | `credgate.new_token_key()`, `credgate.key_fingerprint()` |
| Detectors | `cg_detectors()`, `new_detector()`, `register_detector()`, `reset_detectors()`, `load_detectors()`, `bounded()` | `credgate.detectors()`, `credgate.Detector`, `register_detector()`, `reset_detectors()`, `load_detectors()`, `bounded()` |
| Normalise | `cg_normalise()` | `credgate.normalise()` |
| Mask a value | `mask_value()`; `options(credgate.mask = "full")` | `credgate.mask_value()`; `credgate.set_mask("full")` |
| Checksums | `verhoeff_valid()`, `verhoeff_check_digit()`, `luhn_valid()`, `luhn_check_digit()`, `gstin_valid()`, `gstin_check_char()` | the same names in `credgate` |
| Column scan | `scan_pii()` | `credgate.scan_pii()` |
| Inventory | `pii_inventory()`, `write_inventory()`, `read_inventory()` | `credgate.pii_inventory()`, `.write()`, `credgate.read_inventory()` |
| Databases | `inventory_database()`, `redact_query()` (DBI) | `credgate.database.inventory_database()`, `redact_query()` (SQLAlchemy) |
| BigQuery | `bq_scan_pii()`, `bq_pii_inventory()`, `bq_inventory_dataset()` | `credgate.bigquery.scan_pii()`, `pii_inventory()`, `inventory_dataset()` |
| Parquet | `redact_parquet()` | `credgate.arrow.redact_parquet()` |
| Policies | `cg_policy()`, `policy_decide()`, `policy_apply()` | `credgate.Policy.load()`, `.decide()`, `.apply()` |
| Saving policies | `policy_write()`, `policy_diff()`, `policy_changes()` | `credgate.write_policy()`, `policy_diff()`, `policy_changes()` |
| Policy tests | `run_policy_tests()` | `credgate.run_policy_tests()` |
| Audit log | `cg_audit_log()`, `audit_record()`, `audit_verify()`, `audit_read()`, `audit_prune()` | `credgate.AuditLog`, `.record()`, `audit_verify()`, `audit_read()`, `audit_prune()` |
| Policy editor | `policy_editor()` | `credgate.editor.policy_editor()`, `credgate editor` |
| Proxy keys | `proxy_add_user()`, `proxy_rotate_key()`, `proxy_remove_user()`, `proxy_users()`, `proxy_access()` | `credgate.proxy_keys.add_user()`, `rotate_key()`, `remove_user()`, `list_users()`, `read_access()` |
| Users file | `cg_users()` | `credgate.users.read_users()` |
| Evaluation, test data | `cg_evaluate()`, `cg_read_corpus()`, `synth_indian_pii()` | `credgate.evaluate()`, `credgate.load_corpus()`, `credgate.synth_indian_pii()` |
| The spec | `cg_spec_path()` | `credgate.spec_path()` |

## Only in Python

- **The proxy** (`credgate proxy serve`). It is a server, run once for a
  team or per machine; R and every other tool use it through its URL - for
  example `ellmer::chat_openai(base_url = "http://127.0.0.1:8790/v1")`.
- **Managing users and unused keys on the server**: `credgate users ...`
  (who may use the app, and their roles) and `credgate proxy
  expire-unused`. Whoever runs these on the server is the super admin; the
  R package reads the users file but does not change it.
- **The command line**: `credgate detect`, `redact`, `scan`, `policy test`
  and the rest, for shells, CI and pre-commit hooks.
- **Polars, pandas and DuckDB SQL functions**: Python data tools without an
  R counterpart. In R, the same work goes through data frames, Arrow, dbplyr
  and DBI.

## Small differences

- **Masking everything**: R takes an option (`options(credgate.mask =
  "full")`), Python a function (`credgate.set_mask("full")`); both also read
  the environment variable `CREDGATE_MASK`.
- **The tests file** (`bank.tests.yaml`): each editor writes it with its
  language's own YAML library, so quoting, indentation and line breaks can
  differ. The contents are the same, and either language reads either.
- **The Python policy editor with Nix on Python 3.11**: nixpkgs cannot
  build Shiny for Python for 3.11, so install it from PyPI there (`pip
  install 'credgate[editor]'`).
- **Releases**: the Python package is on PyPI. The R package's first version
  is under review at CRAN; until it is accepted, everything since is in the
  development version on [R-universe](https://dwarpal.r-universe.dev).
