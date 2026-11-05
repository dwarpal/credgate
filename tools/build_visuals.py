"""Data for the interactive docs visuals (docs/visuals/), computed by credgate
itself so every score, token and decision shown is real.

    PYTHONPATH=pkg/python/src python tools/build_visuals.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import credgate
from credgate._spec import engine
from credgate.detect import explain_pii
from credgate.detectors import get_detectors

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "visuals" / "data.js"

# --- the proxy walkthrough -------------------------------------------------------

POLICY = {
    "policy": "credgate-policy",
    "version": 1,
    "id": "bank-ai",
    "revision": 3,
    "destinations": {
        "claude": {
            "tier": "frontier",
            "provider": "anthropic",
            "url": "https://ai-gateway.bank.internal/anthropic",
        },
        "ollama-local": {"tier": "local", "provider": "ollama", "url": "http://localhost:11434/v1"},
    },
    "rules": [
        {
            "id": "card-with-cvv-and-expiry",
            "when": {"tiers": ["frontier"], "all_of": ["card", "card_cvv", "card_expiry"]},
            "action": "block",
        },
        {
            "id": "ids-tokenised",
            "when": {"tiers": ["frontier"], "classes": ["identity_strong"]},
            "action": "tokenise",
        },
        {
            "id": "contact-redacted",
            "when": {
                "tiers": ["frontier"],
                "classes": ["contact", "financial", "personal", "sensitive_auth"],
            },
            "action": "redact",
        },
        {"id": "local-ok", "when": {"tiers": ["local"]}, "action": "allow"},
    ],
    "default_action": "redact",
}

PROMPT = (
    "Summarise this call: Smt. Sunita Devi, PAN ABCPE1234F, mobile 9876543210, "
    "wants her EMI date moved to the 5th."
)
CARD = "Why was this declined? Card 4111 1111 1111 1111, CVV 123, expiry 08/29."
KEY = "4f9c1e2a7b3d6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071"  # a demo token key


def _matches(decision):
    return [
        {
            "type": m.span.type,
            "class": m.span.data_class,
            "start": m.span.start,
            "end": m.span.end,
            "value": credgate.mask_value(m.span.value, m.span.data_class),
            "confidence": m.span.confidence,
            "action": m.action,
            "rule": m.rule,
        }
        for m in decision.matches
    ]


def proxy_scenarios() -> list[dict]:
    policy = credgate.Policy.from_dict(POLICY)
    out = []
    for sid, title, user, text, dest, refusal in (
        ("frontier", "Analyst to Claude", "arjun", PROMPT, "claude", None),
        ("card", "A card with its CVV and expiry", "arjun", CARD, "claude", None),
        ("local", "The same prompt to a local model", "arjun", PROMPT, "ollama-local", None),
        (
            "leaver",
            "A leaver's key",
            "ravi",
            PROMPT,
            "claude",
            (401, "access_revoked", "ravi no longer has access to this proxy."),
        ),
        (
            "expired",
            "An expired key",
            "meera",
            PROMPT,
            "claude",
            (
                401,
                "key_expired",
                "This credgate proxy key expired on 2026-10-01T00:00:00Z; "
                "ask for a new one (credgate proxy rotate-key).",
            ),
        ),
    ):
        s = {
            "id": sid,
            "title": title,
            "user": user,
            "endpoint": dest,
            "tier": POLICY["destinations"][dest]["tier"],
            "text": text,
        }
        if refusal:
            s.update(refused={"status": refusal[0], "code": refusal[1], "message": refusal[2]})
            out.append(s)
            continue
        vault = credgate.Vault(bytes.fromhex(KEY))
        with tempfile.TemporaryDirectory() as d:
            log = credgate.AuditLog(Path(d) / "audit.jsonl", actor=user)
            decision = policy.apply(text, dest, vault=vault, audit=log)
            record = credgate.audit_read(Path(d) / "audit.jsonl")[0]
        s["matches"] = _matches(decision)
        s["allowed"] = decision.allowed
        s["blocked_by"] = list(decision.blocked_by)
        record["time"] = "2026-11-06T10:42:07.512Z"
        record["prev"] = record["prev"][:12] + "..."
        s["audit"] = record
        if decision.allowed:
            sent = decision.texts[0]
            s["sent"] = sent
            if dest == "claude":
                pan = next(t for t in _tokens(sent) if t.startswith("[PAN_"))
                answer = (
                    f"Customer {pan} asked to move the EMI date to the 5th; "
                    "call back on [MOBILE_IN] to confirm."
                )
            else:
                answer = (
                    "Customer ABCPE1234F (Sunita Devi) asked to move the EMI date to the 5th; "
                    "call back on 9876543210 to confirm."
                )
            s["answer"] = answer
            s["restored"] = credgate.restore(answer, vault)
        else:
            s["refused"] = {
                "status": 403,
                "code": "policy_blocked",
                "message": "Blocked by policy bank-ai (revision 3): "
                + ", ".join(decision.blocked_by),
            }
        out.append(s)
    return out


def _tokens(text: str) -> list[str]:
    import re

    return re.findall(r"\[[A-Z_]+_[a-z0-9]+\]", text)


# --- the scoring explorer ----------------------------------------------------------

EXAMPLES = [
    ("Aadhaar with its label", "Aadhaar 2345 6789 0124"),
    ("The same number, no label", "Noted 2345 6789 0124 on file"),
    ("In an order number", "order no 234567890124"),
    ("One digit mistyped", "Aadhaar 2345 6789 0125"),
    ("Devanagari digits", "आधार २३४५ ६७८९ ०१२४"),
    ("A hidden character", "PAN ABC​PE1234F"),
    ("Mobile with a label", "mobile 9876543210"),
    ("Mobile, no label", "call 9876543210 tomorrow"),
    ("Account number with 'a/c'", "a/c 123456789012"),
    ("Account number, no keyword", "ref 123456789012"),
    ("Voter ID with 'voter'", "voter ID QMF1202883"),
    ("Voter ID alone", "batch QMF1202883"),
]


def scoring_examples() -> list[dict]:
    dets = {d.id: d for d in get_detectors(None)}
    out = []
    for title, text in EXAMPLES:
        norm = credgate.normalise(text)
        matches, misses = explain_pii(text)
        found = []
        for s in matches:
            det = dets[s.type]
            reasons = s.reasons.split("; ")
            ctx = next((r[9:-1] for r in reasons if r.startswith("context '")), None)
            neg = next((r[18:-1] for r in reasons if r.startswith("negative context '")), None)
            base = _base(det, s, ctx, norm)
            found.append(
                {
                    "type": s.type,
                    "label": det.label,
                    "start": s.start,
                    "end": s.end,
                    "value": s.value,
                    "checks": det.checks,
                    "base": base,
                    "context": ctx,
                    "negative": neg,
                    "confidence": s.confidence,
                    "reasons": reasons,
                }
            )
        out.append(
            {
                "title": title,
                "text": text,
                "normalised": norm.text,
                "changed": norm.text != text,
                "matches": found,
                "misses": [
                    {
                        "type": m.type,
                        "label": dets[m.type].label,
                        "start": m.start,
                        "end": m.end,
                        "value": m.value,
                        "why": m.why,
                    }
                    for m in misses
                ],
            }
        )
    return out


def _base(det, span, ctx, norm) -> float:
    """The detector's starting confidence for this match, before context."""
    if ctx is None and det.base_without_context is not None:
        return det.base_without_context
    if callable(det.base):
        s, e = span.start, span.end
        if norm.map is not None:  # back to normalised offsets
            s = norm.map.index(span.start)
            e = norm.map.index(span.end - 1) + 1
        return det.base(norm.text[s:e])
    return det.base


def main() -> None:
    scoring = engine()["scoring"]
    data = {
        "proxy": {"policy": POLICY, "scenarios": proxy_scenarios()},
        "scoring": {
            "context_boost": scoring["context_boost"],
            "negative_factor": scoring["negative_factor"],
            "window": scoring["context_window"],
            "examples": scoring_examples(),
        },
        "version": credgate.__version__,
    }
    OUT.write_text(
        "// Generated by tools/build_visuals.py from credgate "
        f"{credgate.__version__}; do not edit.\n"
        "window.CG_DATA = " + json.dumps(data, ensure_ascii=False, indent=1) + ";\n",
        encoding="utf-8",
    )
    print("wrote", OUT)


if __name__ == "__main__":
    main()
