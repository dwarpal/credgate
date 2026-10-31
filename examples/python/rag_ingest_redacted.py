# ruff: noqa: E501  (example sentences read better unwrapped)
"""Scan and redact documents before chunking them into a RAG index.

A vector store keeps every chunk it is given, so PII that goes in stays in.
Redact before indexing; this example prints what would be indexed.

Requires: pip install credgate
Run:      python examples/python/rag_ingest_redacted.py

All data below is synthetic.
"""

import credgate

documents = {
    "kyc_notes.txt": "Name: Anjali Rao. Voter ID FSO6231132. Address: House No 7, Civil Lines, Jaipur 302006.",
    "policy.txt": "Loans above Rs 10,00,000 need a second approver. Branch hours are 10:00-16:00.",
    "call_0412.txt": "Mera PAN abcpe1234f hai, mobile no. 9876543210 pe OTP bhejo.",
}

# 1. Which documents contain PII at all? (Useful as an inventory.)
report = credgate.scan_pii({"text": list(documents.values())})
print(report, end="\n\n")

# 2. Redact, then chunk; only redacted chunks would be embedded and stored.
for name, text in documents.items():
    safe = credgate.redact(text, min_confidence=0.5)
    chunks = [safe[i : i + 80] for i in range(0, len(safe), 80)]
    print(f"{name}: {len(chunks)} chunk(s)")
    for chunk in chunks:
        print(f"  {chunk}")
