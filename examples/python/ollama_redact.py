"""Redact PII before sending text to a local Ollama model.

Requires: pip install credgate ollama   (and a running Ollama server)
Run:      python examples/python/ollama_redact.py [model]   (default: gemma3:1b)

All data below is synthetic.
"""

import sys

import credgate
import ollama

MODEL = sys.argv[1] if len(sys.argv) > 1 else "gemma3:1b"

note = (
    "Customer name: Priya Nair. Called about her home-loan EMI. PAN ABCPN1234K, "
    "mobile +91 98765 43210, UPI priya.n@oksbi. She wants the EMI date moved "
    "to the 10th because her salary is credited late."
)

# 1. See exactly what would leave the machine, and why. Always check this:
#    names in running text without an honorific or label (e.g. "Customer
#    Priya Nair called") are not detected yet.
print(credgate.preview(note, min_confidence=0.5))

# 2. Redact: identifiers become placeholders such as [PAN] and [PERSON_NAME].
safe = credgate.redact(note, min_confidence=0.5)

# 3. Only the redacted text reaches the model.
reply = ollama.chat(
    model=MODEL,
    messages=[{"role": "user", "content": f"Summarise this call note in one sentence:\n{safe}"}],
)
print("\nModel reply:\n" + reply.message.content)
