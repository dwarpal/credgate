# Get started with Python

```sh
pip install credgate                     # core: regex and PyYAML only
pip install "credgate[all]"              # with Arrow, Polars, DuckDB, BigQuery and saved vaults
```

## Find PII

```python
import credgate

note = "Customer name: Priya Nair. PAN ABCPN1234K, mobile +91 98765 43210."
for span in credgate.detect_pii(note):
    print(span.type, span.confidence, span.reasons)

print(credgate.preview(note))            # what would be masked, and why
```

## Redact before a model sees the text

```python
safe = credgate.redact(note, min_confidence=0.5)
# "Customer name: [PERSON_NAME]. PAN [PAN], mobile [MOBILE_IN]."
```

## Tokenise, then restore the model's answer

```python
vault = credgate.Vault()
safe = credgate.tokenise(note, vault)    # "... PAN [PAN_1] ..."
answer = "Updated the record for [PAN_1]."
print(credgate.restore(answer, vault))   # the real PAN, only on your machine
```

## Scan tables and build an inventory

```python
import pandas as pd

customers = pd.DataFrame(credgate.synth_indian_pii(100, seed=1))   # synthetic data
print(credgate.scan_pii(customers))

inv = credgate.pii_inventory(customers, source="crm", table="customers")
inv.write("inventory.csv")
```

Spark DataFrames and BigQuery tables are sampled where they live - see
[inventory and discovery](api/inventory.md) and the
[large-data guide](../large-data.md).

## Apply a policy, and keep an audit log

```python
policy = credgate.Policy.load("examples/policies/bank-default.yaml")
log = credgate.AuditLog("audit.jsonl")
decision = policy.apply(note, "claude", audit=log)
print(decision)                          # allowed or blocked, and why
```

The same features exist in R with the same results; see the
[R package site](https://dwarpal.github.io/credgate/r/).
