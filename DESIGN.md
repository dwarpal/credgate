# Design: governance-first R assistant for regulated Indian environments

Status: draft v0.1 (2026-10-31). Scope: whole architecture in brief, phase 1 in detail.

## 1. Packaging decision: two packages, one repo

| Package | Role | Deps | Why separate |
|---|---|---|---|
| **governance core** | PII detection, `scan_pii`, `preview`, redact/tokenise/restore, policies, routing decisions, audit log, proxy mode (phase 2) | very lean | Compliance teams approve every dependency. A small, auditable package can go into production Shiny apps, plumber APIs and batch pipelines that will never load a chat UI. |
| **assistant** | provider layer, chat UI, IDE adapter, tools, notebooks, MCP client/server, skills, `ask()` | heavier (shiny, shinychat, processx, …) | Imports the core. Every outbound call goes through the core's `govern()` API; there's no other way out. |

Layout: a monorepo with `pkg/<core>/` and `pkg/<assistant>/`, shared CI, released separately (this matches "each phase released on its own").

**Decided:** the core is `credgate` (in `pkg/credgate/`); the assistant takes a name from the same family later.

### Name ideas (all currently free on CRAN, checked 2026-10-31)

| Core (gatekeeper) | Assistant (helper) | Note |
|---|---|---|
| **`dwarpal`** (द्वारपाल, "gatekeeper") | **`sahayak`** (सहायक, "assistant") | My pick: a matched pair, short, and Indian without being cute |
| `credgate` | `sahayak` | Use this if CredGate is your proxy project's brand, so the R core sits in the same family |
| `pehredar` ("watchman") | `saathi` ("companion") | |

Avoid `kavach`. It's free on CRAN, but Indian Railways and several government security products already use it.

## 2. Module structure

### Shared detection spec (decided 2026-10-31)

Detector rules, engine parameters and conformance cases live in `spec/` (see
`spec/README.md`) and are shared by the R and Python packages; the
`detectors-*.R` files below are replaced by `spec/detectors.yaml`, compiled by
`R/spec.R`. `tools/sync-spec.sh` copies `spec/` into `pkg/credgate/inst/spec`.
Patterns use the regex subset common to ICU and Python `regex` (verified
identical on all conformance texts). The Python package (`pkg/python`,
`import credgate`, Python >= 3.11, deps `regex` + `PyYAML`) passes the same
conformance suite; its API is Pythonic (0-based end-exclusive spans,
`Span` objects with masked `repr`) but finds identical matches. It ships the
CLI: `credgate detect [--lines] [--json] [--reveal] [--fail]`, `credgate
detectors`, `credgate spec-path`; `scan`, `preview`, `audit` and `proxy`
follow with phase 1-2. The proxy is likely Python.

### Core package (phase 1 is in bold)

```
R/
  normalise.R          **Unicode NFKC, Indic digits→ASCII, zero-width strip, offset map back to the original**
  checksums.R          **verhoeff(), luhn(), gstin_check() (mod-36), vectorised**
  detectors.R          **detector registry: new_detector(id, class, pattern, validate, context, score)**
  detectors-id.R       **aadhaar, aadhaar_vid, pan, voter_epic, passport, driving_licence**
  detectors-finance.R  **gstin, upi_id, ifsc, bank_account (context-gated), card (Luhn)**
  detectors-contact.R  **mobile_in (+91/0/bare 6-9xxxxxxxxx), email, pincode (quasi)**
  detectors-health.R   **abha_number (14-digit), abha_address (@abdm/@sbx)**
  detectors-names.R    **rule-based names/addresses: honorifics (Shri/Smt/श्री/श्रीमती), S/o D/o W/o C/o, address
                        lexicon (Nagar, Marg, Tehsil, जिला…), Indic-script runs; pluggable NER hook**
  detect.R             **detect_pii(text) → spans with type, class, confidence, reasons**
  scan.R               **scan_pii(df): column report with sampling, column-name hints, masked examples only**
  vault.R              **session vault: value↔token, deterministic within a session, in-memory by default**
  transform.R          **redact() / tokenise() / restore(); restore_stream() handles tokens split across chunks**
  preview.R            **preview(text): cli highlight of what gets masked plus the policy decision**
  policy.R             **YAML load/validate/merge, data classes, endpoint attributes, decide() → decision object**
  route.R              **pick an endpoint that satisfies the decision (location: local/on_prem/in_india/global)**
  audit.R              **append-only JSONL, SHA-256 hash chain, audit_read(), audit_verify()**
  audit-report.R       **audit_export(format = "html"|"csv"): self-contained HTML, no CDN (air-gap safe)**
  govern.R             **govern(request, endpoint, session): the single entry point everything calls**
  config.R             **user config in tools::R_user_dir(); additive migration; keys only from env vars**
  synth.R              **synth_indian_pii(): synthetic generator (valid checksums) for tests/demos**
  proxy-*.R            phase 2: httpuv OpenAI-compatible server, SSE passthrough with streaming restore
  panel/               phase 2: status panel (static HTML + JSON poll), viewer-hosted
inst/policies/         **dpdp-strict.yaml, rbi-bfsi.yaml, internal-only.yaml (editable copies)**
inst/regulatory/       **obligation catalogue: DPDP Act 2023/Rules 2025, RBI, SEBI CSCRF, IRDAI refs**
```

### Assistant package (phases 3–5, outline only)

```
R/provider-*.R     core.R (S7 classes: Turn, Content{text,thinking,tool_call,tool_result,image}),
                   ollama.R (/api/chat, /api/ps for runtime num_ctx, think, keep_alive),
                   openai.R (compatible: vLLM, LM Studio, gateways, Azure), anthropic.R, gemini.R, bedrock.R
                   stream.R (one SSE/NDJSON parser → uniform events), capabilities.R, ellmer-adapter.R
R/history.R        turn validation, broken-turn purge, model-switch cleanup, real-token trimming
R/ide-*.R          adapter.R (generic API) + rstudio.R / vscode.R / positron.R / none.R
R/tools-*.R        files, session (bridge), notebook, data, slurm; lock + dedupe in tools-runtime.R
R/bridge.R         file-based request queue polled by the live session (interrupt-safe, logged)
R/mcp-*.R          client (stdio/HTTP, grouped by server), server (exposes the IDE toolset)
R/env-snapshot.R   change-triggered metadata snapshot (names/classes/dims/col types)
R/chat-app.R       shinychat UI, background process, viewer display, reconnect/restore
R/skills.R, agents-md.R, ask.R
```

## 3. Phase 1 design details

### Detection pipeline
1. **Normalise:** NFKC, map Devanagari/Bengali/Gujarati/Gurmukhi/Tamil/Telugu/Kannada/Malayalam/Odia digits to ASCII, strip zero-width and soft-hyphen characters. Keep an offset map so spans point at the *original* text. This stops trivial evasion such as `२३४५ ६७८९ ०१२३` or zero-width characters inside a PAN.
2. **Candidate regex** per detector (stringi, vectorised over a character vector).
3. **Validate:** Verhoeff for Aadhaar/VID, mod-36 for GSTIN (which also yields the embedded PAN), Luhn for cards, state-code tables for DL/GSTIN, PAN 4th-char entity type, Aadhaar first digit 2–9.
4. **Score:** base + checksum boost + context keywords within ±N tokens ("Aadhaar", "आधार", "A/c", "IFSC", "UAN") − penalties (e.g. a 12-digit number next to "order no"). Output is a 0–1 confidence plus the list of reasons, so `preview()` can explain *why*.
5. **Resolve overlaps:** the longest span with the highest confidence wins (GSTIN beats the PAN inside it, email vs UPI is decided by the PSP handle list).

Ambiguous types are context-gated, never matched on the bare pattern: bank account numbers (9–18 digits), voter EPIC, passport, UAN, CKYC.

Names and addresses in Indic scripts and transliteration: phase 1 is rule-based and **recall is limited**. We'll say so in the docs. The `detectors-names.R` hook accepts an external NER function (e.g. a local Ollama model, or an ONNX model later) without changing the API. Default policy treats unclassified free-text columns as `sensitive` until a human marks them otherwise.

### Transform modes (per data class, set by policy)
- `redact`: `[PAN]`, irreversible.
- `tokenise`: `[PAN_3]`, restorable. The same normalised value gives the same token for the whole vault. (Plain brackets, matching `redact()`'s `[PAN]`; models copy them reliably.)
- `surrogate` (phase 1.5): a format-preserving fake that can be restored. Models reason better over realistic values. Synthetic values are chosen so they *fail* real validation (e.g. an Aadhaar starting with 0/1), so they can never be a real person's number.
- `block`: refuse the request and log why.

`restore()` tolerates model mangling (case, spacing, dropped brackets). `restore_stream()` holds back any trailing partial-token prefix between chunks. The vault lives in memory; saving it is opt-in and encrypted with libsodium (scrypt key from a passphrase, XSalsa20-Poly1305), the same file format in R and Python.

### Policy (YAML)
```yaml
name: dpdp-strict
version: 1
classes:
  identity_strong: [aadhaar, aadhaar_vid, pan, passport, voter_epic, driving_licence]
  financial:       [bank_account, card, upi_id, gstin]
  health:          [abha_number, abha_address]
  contact:         [mobile_in, email]
  personal:        [person_name, address]
  quasi:           [pincode, ifsc, aadhaar_masked]
endpoints:            # attributes, not hard-coded providers
  local-ollama: {location: local}
  azure-in:     {location: in_india, provider: azure}
  openai:       {location: global}
rules:
  - when: {class: [identity_strong, health]}
    action: tokenise
    allow_locations: [local, on_prem, in_india]
  - when: {class: financial}
    action: tokenise
  - when: {min_confidence: 0.5, class: quasi}
    action: redact
default: {action: allow}
obligations:          # informational mapping, shown in audit reports
  identity_strong: [DPDP-2023 s.8(5) reasonable security safeguards, DPDP-2023 s.16 cross-border]
```
`decide(detections, endpoint, policy)` returns an S7 `Decision` with the action per span, whether the endpoint is allowed, a suggested reroute, and the reasons with rule ids. The regulatory mapping is informational. The docs will state that the mapping is not legal advice and that the compliance team owns the presets.

### Audit log
JSONL, one record per request:

```
ts, request_id, session_id, entrypoint (wrapper|proxy|chat|ask), os_user, policy{name,version,sha256}, endpoint, location, model,
detections[{type,class,count,max_conf}], actions, decision, tokens{in,out}, latency_ms, status, prev_hash, hash
```

- No raw PII is stored by default. Detected values are recorded only as HMAC-SHA256 with a per-install key, so you can answer "was this Aadhaar ever sent?" without storing the Aadhaar.
- Before/after views for the status panel come from the in-memory vault, plus an optional encrypted store.
- `audit_verify()` walks the hash chain to detect tampering.
- `audit_export()` writes CSV, or a single-file HTML report with filters and summary tables, using no external assets.

### Phase 1 public API
```r
detect_pii(text, detectors = NULL)            # spans
scan_pii(df, sample = 10000, min_rate = 0.05) # column report, masked examples
preview(text, policy = "dpdp-strict", endpoint = NULL)
s <- gov_session(policy = "dpdp-strict")
out <- redact(text, session = s)              # mode from policy, or override
restore(model_reply, session = s)
govern(request, endpoint, session = s)        # decide + transform + audit; used by every later phase
policy_presets(); policy_load(); policy_edit()  # copies a preset to the user dir
audit_read(); audit_verify(); audit_export("report.html")
synth_indian_pii(n = 100)
```

### Phase 1 acceptance criteria
- Synthetic corpus (English, Hindi, Hinglish, mixed scripts, Indic digits, OCR-ish noise) checked into `tests/testthat/fixtures`, generated by `synth_indian_pii()`, never real data.
- Checksum detectors (Aadhaar, GSTIN, card): precision ≥ 0.99, recall ≥ 0.99. Context-gated types: published per-type precision/recall in a benchmark vignette. No hidden numbers.
- `scan_pii()` on a 1M-row × 20-col data frame finishes in under 10 s by sampling.
- Round trip: `restore(redact(x)) == x` on the corpus, including streamed restore with random chunk boundaries.
- `audit_verify()` detects any edited, deleted or reordered line.
- R CMD check clean, and no network access in tests.

## 4. Dependencies and licenses

Apache-2.0 for our code. Importing MIT/BSD/GPL-≥2 R packages is fine: we don't vendor them, and Apache-2.0 is compatible with GPL-3. Avoid GPL-2-*only* code and don't vendor anything.

| Package | License | Where | Use |
|---|---|---|---|
| cli, rlang, glue | MIT | core Imports | messages, errors, preview rendering |
| stringi | BSD-style (ICU) | core Imports | vectorised regex, NFKC, script detection |
| jsonlite | MIT | core Imports | JSONL audit, JSON IO |
| yaml | BSD-3 | core Imports | policies, config |
| openssl | MIT | core Imports | SHA-256 chain, HMAC, AES-GCM |
| S7 | MIT | core Imports | Detection/Decision/Policy classes |
| fs, withr | MIT | Suggests/Imports | paths; test hygiene |
| httpuv | GPL-≥2 \| custom | core Suggests (phase 2) | proxy server |
| httr2 | MIT | phase 2–3 | upstream calls, streaming |
| testthat, webfakes | MIT | Suggests | tests, fake provider servers |
| shiny, bslib, shinychat | MIT | assistant | chat UI |
| processx / callr | MIT | assistant | background app, Slurm, processes |
| rstudioapi | MIT | assistant | RStudio and vscode-R emulation |
| mcptools, btw | MIT | evaluate in phase 5 | MCP transport, tool ideas |
| ellmer | MIT | assistant Suggests | optional adapter only |

Deliberately left out: DBI/RSQLite (JSONL is enough and easier to ship to auditors), data.table/arrow, and anything that downloads models at runtime.

### Nix and nixpkgs (requirement)

Every package must build and pass its tests in the Nix sandbox (no network,
read-only `HOME`, no IDE). The repo `flake.nix` builds `credgate-r` with
`rPackages.buildRPackage` (as nixpkgs does) and runs `checks`: the test suite
against the installed package and `spec-in-sync`. CI runs `nix flake check
--all-systems` on Linux and macOS.

Rules that keep this true: tests never write outside `tempdir()`/`tmp_path`
(config and audit paths are overridable by env var); tests that start
processes or open ports skip under `NIX_BUILD_TOP`; runtime data (`spec/`) is
packaged, never read from the repo; no downloads at build or run time; only
dependencies already in nixpkgs.

Route into nixpkgs: R packages there are generated from CRAN, so `credgate`
reaches `rPackages` by being published on CRAN (no hand-written derivation).
The Python package gets a derivation under
`pkgs/development/python-modules/credgate` (and the CLI a top-level
`credgate` via `toPythonApplication`); both maintainers need entries in
`maintainers/maintainer-list.nix` (name, email, GitHub handle and numeric id).

### No shared C++/Rust core (decided 2026-10-31)

The spec plus conformance suite already gives one source of truth for the
rules. A compiled core would add wheel/CRAN binary builds and compilers on
locked-down machines, and the hot path is already native (ICU, `regex`).
RE2 cannot express our lookarounds. Revisit if profiling shows the R/Python
engine code (not regex) dominates, or a third language (JS/JVM) is needed;
then prefer Rust (`extendr` + PyO3).

Local R packages come from the user's Nix overlay (`bundles/hash-bundle-sikka/r-packages.nix`); add new Imports/Suggests there rather than adding a flake to this repo. `~/.Renviron` pins `R_LIBS_SITE` to the installed bundle, so after changing the list either reinstall the bundle and rerun `scripts/configure-positron-r.sh`, or run a freshly built R with `R_ENVIRON_USER=/dev/null`. Process-starting tests must skip in sandboxed builds (detect `NIX_BUILD_TOP`, plus `skip_on_cran()`).

## 5. Positioning (to verify in detail during phases 3–5)

**Decided 2026-10-31.** Detection on its own is easy to copy (Presidio,
Macie, Google DLP, anyone's regexes), so it is the engine, not the product.
The product is: *use LLMs on regulated Indian data, and be able to prove
you did it safely.* What sets credgate apart:

- **Proof, not only protection:** reversible tokenisation, a proxy in
  front of local or hosted models, policies and a hash-chained audit log a
  DPO can show a regulator under DPDP.
- **Rules as a feature:** deterministic, explainable decisions
  ("Verhoeff checksum passed, near 'Aadhaar'"), identical in R and Python,
  offline and fast. Auditors can read why something was flagged.
- **Where data scientists work:** data frames, notebooks, RStudio,
  Positron and VS Code, not only engineering pipelines.
- **India in depth:** Indic scripts, Hinglish, official reference lists
  (PIN codes, IFSC, UPI handles) and matching against a customer master,
  rather than India as one more region.

Two gaps to close: accuracy evidence is synthetic only (get a small
real-world evaluation set annotated with a partner, never committed), and
the direction is not yet validated with users (talk to 4-5 data science or
compliance people at banks, NBFCs and insurers).

| Tool | What it is | How we differ |
|---|---|---|
| ellmer | LLM client library | We add policy/PII/audit before egress, native Ollama ctx/think, and runtime context; optional wrapper over ellmer chats |
| shinychat | chat UI component | We use it, not compete with it |
| btw / mcptools | context tools / MCP bridge for R | Candidates to reuse; we add the governance lock, IDE adapter parity and notebook reliability rules |
| chores, gander | ellmer-based editor helpers | Single-purpose, no governance |
| gptstudio, chattr | earlier chat add-ins | No policy layer, limited providers/tools, no audit |
| Posit Assistant | commercial (subscription or BYOK) | Closed, no Indian PII or DPDP mapping, no air-gapped local-only governance. Proxy mode can *govern it* too (BYOK base URL) |

## 6. Improvement roadmap (agreed 2026-10-31)

Status as of py-v0.5.0 / CRAN 0.1.0 (under review). The evaluation
harness (item 1) is done. **Reordered 2026-10-31** (see section 5):
accuracy is already ahead of the alternatives on our benchmark, so after a
few quick accuracy fixes the next work is the product chain - tokenise and
restore (4), then proxy mode with policy (5) and audit (6) - with security
and maturity throughout. Further accuracy work (2, 3) follows, using
deterministic methods only: official reference lists (PIN code directory,
IFSC master, UPI handles, state and RTO codes, a names list checked for
regional coverage), propagating a confirmed name through its document,
cross-field checks (GSTIN contains the PAN), salted-hash matching against a
customer master, learned linear scoring weights stored in the spec in place
of hand-tuned constants, and later grammars for addresses and k-anonymity
risk for tables. Neural NER only as an optional, clearly labelled extra
layer.

### Build order for the governance features (agreed 2026-11-01)

Done since 0.4.0: reversible tokenisation with encrypted vault files,
large-data support in Python and R (pandas, Polars, Arrow/Parquet, DuckDB,
DBI databases including Postgres), a throughput benchmark. The next pieces
are built in dependency order, so nothing is built twice or retrofitted
(see [docs/threat-model.md](docs/threat-model.md) for the reasoning):

1. **Threat model** (done: docs/threat-model.md).
2. **Keyed tokens** in the spec (done): HMAC-SHA256 of type and canonical
   value, 64-bit base32 ids, key fingerprints, merging, keyed vault files;
   identical in R and Python. Needed by the audit log, the proxy and
   parallel engines.
3. **New detectors** (done): card verification code (data class
   `sensitive_auth`, never stored) and expiry, CKYC, ration card, NREGA job
   card numbers; in the benchmark corpus (version 2).
4. **Policy engine** in the spec: destinations (local, internal, frontier),
   rules on combinations (card + CVV + expiry -> block), fail closed,
   versioned. Same YAML in R and Python.
5. **Audit log** in the spec: keyed hashes only, hash chain, policy version
   per record, retention default 5 years (minimum 1), on-premises.
6. **Discovery at scale**: Spark (PySpark, sparklyr), BigQuery, a
   warehouse-wide PII inventory - using keyed tokens, policies and audit.
   Detection-only scanning can move earlier if a concrete need arises.
7. **Proxy** (Python): offline, localhost by default, a Nix-built image.
8. **Shiny apps** in R and Python: a policy editor for InfoSec and
   compliance (possible after 4) and the assistant (after 7); thin, with all
   decisions in the policy engine and proxy.

Inputs for this order came from user interviews (kept outside the
repository) and a review of DPDP, RBI, CERT-In and PCI DSS obligations.

| # | Area | Today | To do |
|---|---|---|---|
| 1 | Accuracy benchmarking | `evaluate()` in both packages; synthetic labelled corpus (dev/test); per-type report in `benchmark/README.md` (test F1 0.947 at 0.5); compared with Presidio (F1 0.949 vs 0.666 India-configured on common types) | Labelled synthetic corpus; per-type precision, recall, F1; published report. Compare with Microsoft Presidio (MIT, has Indian recognisers); verify that other named tools exist, run locally and allow published benchmarks before comparing |
| 2 | False positives | Checksums, negative context, context-required types, confidence scores | Hard-negative sets (order/invoice/transaction IDs, amounts, product codes); measure, then tighten (bare 12-digit Aadhaar, bare 10-digit mobile, capitalised words after honorifics) |
| 3 | Multilingual | Devanagari keywords/digits, digits in 11 scripts, names after Hindi honorifics/labels | Keywords for more Indic languages, Hinglish and transliterated cues, optional statistical name detector via the detector hook |
| 4 | Reversible masking | `redact()`, `preview()`; `tokenise()`/`restore()`, tolerant restore, strict mode; encrypted vault files (passphrase, scrypt + XSalsa20-Poly1305, same file in R and Python) | Stronger key derivation (R `sodium::argon2()` is broken in 1.4.0, so scrypt at libsodium's interactive limits for now), keychain/KMS keys, access control on restore, expiry/purge, streaming restore |
| 5 | Policy engine | Designed (section 3) | Presets, data classes, endpoint-specific rules; allow / redact / mask / tokenise / block |
| 6 | Audit and compliance | Designed (section 3) | Hash-chained records of detections and decisions, no raw PII, DPDP-oriented reports (HTML/CSV) |
| 7 | Security | Masked output by default, no PII in logs, SHA-pinned CI actions, C-locale tests | Threat model; property-based fuzzing (Unicode, invisible characters, long inputs, regex blow-up); adversarial cases |
| 8 | Project maturity | Tagged releases, CI on Linux and macOS, Nix sandbox tests | API stability and compatibility policy; integration and corpus-driven regression tests; 1.0 after items 4-6 |

## 7. Open questions for you
1. Package names: `dwarpal` + `sahayak`, or the `credgate` family? What is the proxy project called, and should the policy YAML and audit schema be *shared* with it (one format for both)?
2. Should phase 1 include `surrogate` mode, or ship with `redact`/`tokenise` only?
3. Minimum R version: I suggest R ≥ 4.3 for S7 and native pipe. Do your target bank environments run older R?
