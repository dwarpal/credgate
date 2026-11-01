"""Tokenise PII, let a local Ollama model draft a reply, then restore the values.

The model only sees tokens such as [PERSON_NAME_1] and [PAN_1]; the real
values go back into its draft afterwards, on this machine.

Requires: pip install credgate ollama   (and a running Ollama server)
Run:      python examples/python/ollama_tokenise_restore.py [model]   (default: gemma3:1b)

All data below is synthetic.
"""

import sys

import credgate
import ollama

MODEL = sys.argv[1] if len(sys.argv) > 1 else "gemma3:1b"

note = (
    "Customer name: Priya Nair. PAN ABCPN1234K, mobile +91 98765 43210. "
    "She wants the EMI date moved to the 10th because her salary is credited late."
)

# 1. Tokenise: the vault remembers which value each token stands for.
vault = credgate.Vault()
safe = credgate.tokenise(note, vault, min_confidence=0.5)
print("Sent to the model:\n ", safe, "\n")

# 2. Only tokens reach the model. Ask it to keep them as they are.
reply = ollama.chat(
    model=MODEL,
    messages=[
        {
            "role": "system",
            "content": "Keep tokens such as [PERSON_NAME_1] exactly as written.",
        },
        {"role": "user", "content": f"Draft a two-line reply to this customer:\n{safe}"},
    ],
)
draft = reply.message.content
print("Model's draft:\n ", draft, "\n")

# 3. Restore on this machine. strict=True would stop on a token the model
#    invented; here unknown tokens are simply left as they are.
print("Restored:\n ", credgate.restore(draft, vault))
