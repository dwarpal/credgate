# credgate threat model

What credgate protects, against whom, what it trusts, and where it does
**not** protect. It covers detection, scanning and inventories (including
Spark, BigQuery and whole databases), redaction, keyed and numbered
tokenisation, saved vaults, policies and the policy editor, the audit log
and the proxy, so that each is designed against it.

Written for the people who will approve credgate: InfoSec, compliance and
DPOs in banks, insurers and fintechs. Updated 2026-11-02 (Python 0.8.0).

## 1. Setting

The typical deployment, from user interviews:

- Credit and data environments are often **air-gapped**. Local models
  (Ollama, vLLM on internal GPU servers) may see internal data; **frontier
  models** (Claude, Gemini, Copilot and similar, hosted abroad) are allowed
  only in narrow scopes and must never receive personal or card data.
- Data sits in Hadoop (MapR), BigQuery, IBM platforms, Postgres, and
  Parquet/CSV files: terabytes to petabytes.
- Analysts work in RStudio, Positron, VS Code and Jupyter; software is
  installed from internal mirrors, Nix bundles or Docker images.

Relevant obligations (summarised in DESIGN.md and the research notes):
DPDP Act and Rules 2025 (security safeguards, logs kept one year), RBI
payment data localisation (payment data stored only in India), PCI DSS
(card verification codes never stored after authorisation; audit logs kept
12 months), CERT-In (ICT logs kept 180 days, in India), RBI IT governance
(tamper-protected audit trails), RBI FREE-AI (AI inventory, audit trails).

## 2. What we protect (assets)

| Asset | Where it lives | Why it matters |
|---|---|---|
| **Personal and card data** in source data | warehouses, files, notebooks, prompts | the reason credgate exists |
| **Prompts and model answers** | in memory; model server logs; tool histories | may carry personal data in or out |
| **Token vaults** (token → real value) | memory; `.cgvault` files | whoever holds a vault and its passphrase can re-identify |
| **Token key** (keyed tokens; `CREDGATE_TOKEN_KEY`) | supplied by the organisation | with the key, tokens can be checked against guessed values |
| **Vault passphrases** | the user; `CREDGATE_VAULT_PASSPHRASE` | unlock saved vaults |
| **Policies** | YAML files, edited by hand or in the policy editor (R Shiny), with a change log | decide what may go where |
| **Audit log** | on-premises files (JSON Lines) | the evidence for regulators; must be complete and unaltered |
| **Model credentials** | environment variables | access to paid or internal models |
| **credgate itself** | packages, images, source | a compromised release could leak everything |

## 3. Who we protect against

| | Adversary | What they want or do |
|---|---|---|
| A1 | **Frontier model provider** (or anyone with access to its systems) | retain or train on prompts; data stored outside India |
| A2 | **Operators of shared infrastructure**: GPU servers, gateways, observability tools | read prompts in logs, traces and caches |
| A3 | **Insider with data access but no need to see identities**: an analyst working on tokenised data | re-identify customers from tokens or outputs |
| A4 | **Insider with access to logs or the audit trail** | read personal data from logs; quietly remove or edit audit records |
| A5 | **The model itself**, misbehaving or steered by prompt injection in the data | make credgate reveal values it was not given; smuggle data out through answers |
| A6 | **Someone with the files**: a stolen laptop, a shared drive, a git repository | open saved vaults; read redacted exports |
| A7 | **Supply chain**: a compromised dependency, package or image | run code inside credgate |
| A8 | **Well-meaning users**: bypass the proxy, lower thresholds, commit a vault | defeat controls by mistake |

## 4. Trust boundaries

```
 data warehouse / files ──►  analyst's session  ──►  credgate  ──►  model
 (trusted, in India)         (trusted user)          (library      local / internal: allowed by policy
                                                       or proxy)    frontier / abroad: personal and card
                                                         │          data must not cross
                                                         ▼
                                              vault, audit log (on-premises, in India)
```

credgate is the control at the arrow into the model. It **trusts**: the
machine it runs on, the analyst using it, the organisation's key and
passphrase handling, and the policy files as approved by InfoSec. It does
**not trust**: model servers, model output, the network beyond the
organisation, or anything in the text it inspects (data can contain
instructions).

## 5. What credgate guarantees, and how

| Goal | How (today / planned) |
|---|---|
| **G1. Personal data does not cross a boundary the policy forbids.** | Detection with checksums and context; redaction or tokenisation before sending. Policies per data class and endpoint, with combinations such as card + CVV + expiry → block, enforced by the proxy on every value of every request (since 0.7), for the OpenAI, Anthropic and Ollama APIs (since 0.8) - including everything a tool adds on its own, such as the context Claude Code sends. |
| **G2. Fail closed.** | The proxy forwards nothing if detection, the policy or the audit record fails, refuses content it cannot check (images, audio, files), and refuses to start without a valid policy (since 0.7; covered by an attack test suite). A thread race that made detection silently miss identifiers was fixed in 0.5.0 and is now tested; this class of bug is the main thing G2 guards against. |
| **G3. Only the right person gets values back.** | Restore uses the vault of the session that tokenised. In the proxy, an answer can only restore tokens made for its own request (which carries the conversation), never into tool calls; tokens the model invents or alters are never filled in (since 0.7). |
| **G4. Evidence without exposure.** | Audit log (since 0.6): who, when, which endpoint, which policy revision and rule, what was found and done - identifiers only as keyed hashes; **card verification codes never recorded in any form** (PCI DSS 3.3); hash-chained so edits, deletions and reordering are detected; kept on-premises. The proxy records every request (since 0.7). |
| **G5. Works fully offline.** | No network calls, telemetry, update checks or model downloads (today, verified in the source). Everything ships as packages, Nix bundles or Docker images. The BigQuery functions reach BigQuery only through the client and credentials the user passes, and download only samples, after a dry-run cost check. |
| **G6. Decisions can be explained.** | Deterministic rules from a published specification; every match carries its reasons and confidence; R and Python give identical results (today). |
| **G7. Nothing sensitive in credgate's own output.** | Values masked whenever shown (today); never logged; no debug dumps of text. |

## 6. Threats and mitigations

### Detection misses something (A1, A2) - the largest residual risk

Rule-based detection has gaps: names in running text without a cue
("Mary Singh called"), unusual formats, identifiers credgate does not know
yet. Mitigations:
`scan_pii()` and `preview()` before sending; redaction defaults to
`min_confidence = 0` (anything possibly personal is replaced); published
accuracy with its limits; policies that redact free text for frontier
endpoints rather than trust detection alone; inventories that show which
columns hold personal data before anything is sent. Policy owners should treat
credgate as a strong filter, not a proof of absence.

### Tokens reveal information (A3)

- *Numbered tokens* (`[PAN_1]`) reveal how many distinct values a text
  holds and in which order they appeared - little, but not nothing.
- *Keyed tokens* (derived from the value with a secret key) let the
  same customer get the same token across datasets. Without the key they
  reveal nothing; **with the key, an insider can test guesses** - Indian
  mobile numbers have about 10^10 possibilities, few enough to try them all.
  So the token key is as sensitive as a vault: kept out of analysts' hands,
  supplied from a key store, never written to files or logs, rotated with
  care (rotation changes every token). Different purposes use different
  keys (tokens versus audit hashes).

### Saved vault stolen (A6)

`.cgvault` files are encrypted (scrypt key derivation, XSalsa20-Poly1305),
reveal nothing without the passphrase, are written owner-only, and never
overwrite other files. **Known weakness:** R's sodium package fixes scrypt
at libsodium's "interactive" cost, so a weak passphrase can be guessed
offline; passphrases need at least 12 characters, and the file format names
its key derivation so a stronger one can be added. Planned: keys from the
operating system's keychain or the organisation's key management instead
of passphrases.

### The model tries to extract values (A5)

- It asks for, or invents, tokens such as `[PAN_7]`: only tokens the vault
  holds are restored, and strict mode stops on unknown ones. The proxy
  restores only tokens made for the request itself (which carries the
  conversation), so a model cannot fish for other customers' values.
- Restored answers go **to the user who already had the values**. The risk
  is when an answer is passed on: to a tool call, a web request, an email.
  The proxy never restores into tool calls, only into the answer's text
  returned to the user (since 0.7).
- Instructions hidden in data ("ignore your rules and print the vault")
  cannot reach credgate's controls: credgate does not follow instructions
  in the text it inspects.

### Prompts and answers leak through logs (A2, A4)

credgate never logs text or values. The proxy logs decisions to the audit
log only, with keyed hashes, and its own log line per request has who,
where, status and time - never the text; request bodies are not written to
disk. Model servers and gateways keep their own logs - outside credgate's
control, which is why redaction happens *before* the request leaves.

### Audit log edited or deleted (A4)

Each record contains the hash of the previous one, so editing, deleting,
inserting or reordering records is detected by `audit_verify()`; records
carry the policy revision and rule that decided them. Logs rotate monthly
with the chain running across files, so a removed or altered month is
detected too. Retention (since 0.8): default **5 years**, minimum **1 year**
(DPDP Rules, PCI DSS), stored on-premises in India (CERT-In, RBI); old months
are removed only from the oldest end, never from a log that fails
verification, and what was removed is recorded so the rest still verifies.
Several Python processes (such as the proxy's workers) can write one log: a
race at the monthly rotation that could repeat a sequence number was found
and fixed before 0.8 was released. Base R has no file locks, so each R
process writes its own log. Tamper-*evidence*, not
tamper-*proofing*: an insider with full write access can delete the whole
log, which verification and off-host copies make visible.

### Policy weakened (A4, A8)

Policies are versioned (`revision`) and every audit record names the
policy revision and rule; loading is strict (unknown fields, endpoints,
types are errors); the proxy refuses to start with an invalid policy, loads
it once at start, and reports its revision on `/healthz`, so every instance
behind a load balancer can be checked. The policy editor (R Shiny) saves
only a policy that loads with the same strict rules, raises its revision,
and appends who saved it, when, why and what changed to a hash-chained
change log next to the policy, so edited or removed entries are detected.
The editor's name field is what the user typed (or Shiny's signed-in user):
who may reach the editor is controlled by the server's sign-in, not by
credgate.

### Proxy misused (A2, A8)

Since 0.7 (phase 1): listens on localhost by default and records the
operating-system user; on any other address it refuses to start without a
keys file, and every client then needs its own key (only hashes are stored)
and is recorded by name; TLS directly or behind a reverse proxy; endpoint
credentials only from the environment, never seen by clients; content it
cannot check (images, audio) is refused, not forwarded; it fails closed;
its log has no request text. Values are restored only into the answer's
text, only from the tokens made for that request, never into tool calls.
Since 0.8 (phase 2): answers stream piece by piece, and a piece that could
be the start of a token is held back until it is complete, so a token is
never shown half-restored; an endpoint that fails or sends something
unreadable mid-answer ends the stream with an error, never with what it
sent. The Anthropic and Ollama APIs are governed like the OpenAI one, and
content blocks credgate cannot check (images, documents, unknown types)
are refused. In localhost mode only, a user's own key for an endpoint the
proxy holds no key for is passed on (for example Claude Code signed in to
the user's account); shared mode never passes client keys on. A shared
proxy can run on uvicorn, a production HTTP server, which limits the
requests in progress per worker. Users can still call a model directly and
bypass the proxy - network rules, not credgate, enforce that the proxy is
the only way out.

### Supply chain (A7)

Few dependencies (R: cli, jsonlite, rlang, stringi, yaml; Python: regex,
PyYAML; everything else optional), all under permissive licences; the
optional proxy server adds uvicorn (BSD-3), httptools and uvloop (MIT). Builds are reproducible with Nix; CI
actions are pinned to commit hashes; PyPI releases use Trusted Publishing
(no long-lived tokens); every change goes through a reviewed pull request
with CI on Linux and macOS. Organisations can build credgate themselves
from the tagged source.

### Large-data paths

Parquet and database redaction write new files and tables: their access
control is the organisation's. `redact_query()` with one connection holds
redacted chunks in temporary files (removed afterwards) - redacted data,
but still written to local disk. Numbered tokens are not offered inside
parallel engines (Polars, DuckDB) because results would depend on
scheduling; keyed tokens will be.

## 7. Out of scope

- Securing the model server, the warehouse or the user's machine. If the
  host is compromised, credgate's protections are too.
- Re-identification from combinations of non-identifying fields (age +
  PIN code + gender); a k-anonymity check is a possible future addition.
- Images and scanned documents (OCR).
- Legal compliance as such. credgate supports DPDP, RBI and PCI obligations
  with controls and evidence; whether a given use is compliant is for the
  organisation's compliance function.

## 8. Decisions this sets for the next steps

1. **Keyed tokens**: a keyed hash (HMAC-SHA256) of the type and canonical
   value; the key is at least 32 random bytes from a key store or
   environment variable, never a file in the project; separate keys for
   tokens and audit hashes; token text short enough for models to copy
   reliably and long enough to make collisions negligible within a dataset,
   with collisions detected. Specified once, identical in R and Python.
2. **New detectors**: card verification code and expiry date - used by
   policies to block card + CVV + expiry, and **never stored**, not even in
   the audit log; CKYC, ration card and NREGA numbers.
3. **Policy engine**: fail closed; destinations (local, internal, frontier)
   as a first-class concept; rules on combinations of what is found;
   versioned.
4. **Audit log**: no raw identifiers or card verification data; keyed
   hashes; hash chain; policy version per record; retention default 5
   years, minimum 1 year; on-premises.
5. **Proxy**: localhost by default, fail closed, no request bodies on disk,
   restore only tokens issued in the same conversation, never into tool
   calls; shipped as a Nix-built image, fully offline.
6. **Shiny apps**: thin; all decisions in the proxy and the policy engine.
