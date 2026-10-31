# credgate

Detects personal data before it leaves the machine, with Indian identifiers
built in: Aadhaar (with Verhoeff checksum), Aadhaar VID, PAN, GSTIN, voter ID,
passport, driving licence, UPI IDs, IFSC, bank accounts, cards, +91 mobile
numbers, ABHA, and names and addresses in Latin and Indic scripts.

The detection rules live in a shared, language-neutral spec, so this package
and the R package `credgate` find exactly the same matches.

```python
import credgate

spans = credgate.detect_pii("Name: Priya Nair; PAN: ABCPN1234K; UPI: priya.n@oksbi")
for s in spans:
    print(s)  # values are masked when printed; s.value holds the match
```

Command line:

```sh
credgate detect notes.txt            # masked report
credgate detect --lines --json data.csv
git diff --cached | credgate detect --fail   # non-zero exit if PII is found
```

All data in the tests is synthetic (`credgate.synth_indian_pii()`).

Licensed under Apache-2.0.
