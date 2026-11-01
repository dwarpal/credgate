"""pandas: find the PII columns of a DataFrame, then redact a text column.

Requires: pip install credgate pandas
Run:      python examples/python/pandas_scan_redact.py

All data below is synthetic.
"""

import credgate
import pandas as pd

recs = credgate.synth_indian_pii(5, seed=1)
df = pd.DataFrame(
    {
        "cust_pan": [r["pan"] for r in recs],
        "mobile": [int(r["mobile"]) for r in recs],
        "loan_amount": [500_000, 1_250_000, 75_000, 300_000, 90_000],
        "notes": [
            f"Shri {recs[0]['name']} asked about prepayment.",
            f"Mobile changed to {recs[1]['mobile']}.",
            None,
            "Branch hours query.",
            f"UPI refund to {recs[4]['upi_id']} pending.",
        ],
    },
    index=[101, 102, 103, 104, 105],
)

# 1. Which columns hold PII, and how much?
print(credgate.scan_pii(df), end="\n\n")

# 2. Redact the free-text column. The result is a Series with the same
#    index and name; missing values stay missing.
df["notes"] = credgate.redact(df["notes"], min_confidence=0.5)

# 3. Structured PII columns are simplest to drop or tokenise as a whole.
safe = df.drop(columns=["cust_pan", "mobile"])
print(safe.to_string())
