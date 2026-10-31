# ruff: noqa: E501  (example sentences read better unwrapped)
"""Redact PII before calling any OpenAI-compatible server: vLLM, Ollama's /v1,
LM Studio, llama.cpp server or an internal gateway.

Requires: pip install credgate openai
Run:
  # vLLM (default):  python -m vllm.entrypoints.openai.api_server --model <model>
  python examples/python/openai_compatible_redact.py
  # Ollama's OpenAI-compatible endpoint instead:
  CREDGATE_BASE_URL=http://localhost:11434/v1 CREDGATE_MODEL=gemma3:1b \
    python examples/python/openai_compatible_redact.py

All data below is synthetic.
"""

import os

import credgate
from openai import OpenAI

BASE_URL = os.environ.get("CREDGATE_BASE_URL", "http://localhost:8000/v1")
MODEL = os.environ.get("CREDGATE_MODEL", "meta-llama/Llama-3.1-8B-Instruct")

tickets = [
    "Shri Ramesh Kumar (Aadhaar 5422 2937 1182) reports a failed UPI payment to ramesh@okaxis.",
    "Account 50100987654321, IFSC HDFC0004567: customer asks to update email to priya.nair@example.org.",
    "General question about branch timings on Saturday.",
]

# Local servers usually ignore the key, but the client requires one.
client = OpenAI(base_url=BASE_URL, api_key=os.environ.get("CREDGATE_API_KEY", "unused"))

for ticket in tickets:
    safe = credgate.redact(ticket, min_confidence=0.5)
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "Classify the ticket as PAYMENTS, PROFILE or GENERAL. Answer with one word.",
            },
            {"role": "user", "content": safe},
        ],
    )
    print(f"{safe}\n  -> {response.choices[0].message.content.strip()}\n")
