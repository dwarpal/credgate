# ruff: noqa: E501  (templates and table rows read better unwrapped)
"""Generate the synthetic, labelled benchmark corpus.

Documents are assembled from templates; every identifier is inserted from
credgate's synthetic generator and its exact span recorded as it is placed,
so labels are correct by construction. All data is synthetic.

Template slots are written {field:type} or {field:type|transform}:
  field      a column of credgate.synth_indian_pii(), or a generator below
  type       the gold label, or "-" for text that is NOT PII (left unlabelled)
  transform  optional formatting of the value (see TRANSFORMS)

Usage (from the repository root, inside `nix develop`):
  PYTHONPATH=pkg/python/src python benchmark/generate_corpus.py
writes benchmark/corpus/dev.jsonl and benchmark/corpus/test.jsonl.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import credgate
from credgate.checksums import verhoeff_check_digit

DEVANAGARI_DIGITS = str.maketrans("0123456789", "".join(chr(0x0966 + i) for i in range(10)))

TRANSFORMS = {
    "plus91": lambda v: f"+91 {v[:5]} {v[5:]}",
    "zero": lambda v: f"0{v}",
    "spaced": lambda v: " ".join(v[i : i + 4] for i in range(0, len(v), 4)),
    "dev": lambda v: v.translate(DEVANAGARI_DIGITS),
    "lower": str.lower,
    "upper": str.upper,
}


# Non-PII look-alikes, inserted unlabelled.
def gen_order12(rng: random.Random) -> str:
    """12 digits; half of them pass the Aadhaar checksum by construction."""
    body = str(rng.randint(2, 9)) + "".join(rng.choice("0123456789") for _ in range(10))
    if rng.random() < 0.5:
        return body + verhoeff_check_digit(body)
    return body + rng.choice("0123456789")


GENERATORS = {
    "order12": gen_order12,
    "amount": lambda r: (
        f"{r.randint(1, 99)},{r.randint(10, 99)},{r.randint(100, 999)}.{r.randint(10, 99)}"
    ),
    "date": lambda r: f"{r.randint(1, 28):02d}/{r.randint(1, 12):02d}/20{r.randint(20, 26)}",
    "otp": lambda r: f"{r.randint(100000, 999999)}",
    "txn": lambda r: "".join(r.choice("0123456789") for _ in range(r.choice([10, 12, 16]))),
    "invoice": lambda r: f"INV-20{r.randint(20, 26)}-{r.randint(1, 99999):05d}",
    "ticket": lambda r: f"{r.choice('ABCDEFGH')}{r.randint(10000, 99999)}",
}

# (category, language, template)
TEMPLATES = [
    # KYC and onboarding forms
    (
        "kyc",
        "en",
        "Name: {name:person_name}\nPAN: {pan:pan}\nAadhaar: {aadhaar:aadhaar|spaced}\nMobile: {mobile:mobile_in|plus91}\nEmail: {email:email}",
    ),
    (
        "kyc",
        "en",
        "Applicant name - {name:person_name}; Voter ID: {voter_epic:voter_epic}; Passport no. {passport:passport}; DOB {date:-}",
    ),
    (
        "kyc",
        "en",
        "Customer: Shri {name:person_name}, Address: {address:address}; Mobile {mobile:mobile_in}",
    ),
    (
        "kyc",
        "en",
        "Nominee - {name:person_name}. Relation: spouse. DL no {driving_licence:driving_licence}.",
    ),
    (
        "kyc",
        "hi",
        "नाम: {name_hi:person_name}; आधार {aadhaar:aadhaar|dev}; मोबाइल {mobile:mobile_in}",
    ),
    ("kyc", "hi", "पता: {address:address}; पिन {pincode:pincode}"),
    # Banking
    (
        "bank",
        "en",
        "Credit to A/c {bank_account:bank_account} IFSC {ifsc:ifsc} of Rs {amount:-} on {date:-}, txn ref {txn:-}",
    ),
    ("bank", "en", "UPI payment of ₹{amount:-} to {upi_id:upi_id} successful. UPI Ref {order12:-}"),
    (
        "bank",
        "en",
        "Your debit card {card:card|spaced} was used for Rs {amount:-} at an ATM. OTP {otp:-}.",
    ),
    (
        "bank",
        "en",
        "Statement: opening balance {amount:-}; invoice {invoice:-}; order no {order12:-} delivered.",
    ),
    ("bank", "en", "GSTIN {gstin:gstin} filed returns; reference {order12:-}; amount {amount:-}."),
    ("bank", "hi", "खाता {bank_account:bank_account} में {amount:-} रुपये जमा हुए"),
    # Call-centre notes (English)
    (
        "callcentre",
        "en",
        "Customer called about loan EMI. Verified PAN {pan:pan} and mobile {mobile:mobile_in|zero}. Ticket {ticket:-}.",
    ),
    (
        "callcentre",
        "en",
        "{name:person_name} called regarding a failed transfer of Rs {amount:-}; asked to share UPI ID {upi_id:upi_id}.",
    ),
    (
        "callcentre",
        "en",
        "Spoke to Smt. {name:person_name}. She updated her email to {email:email} and alternate number {mobile:mobile_in}.",
    ),
    (
        "callcentre",
        "en",
        "Caller gave Aadhaar {aadhaar:aadhaar} for e-KYC; order {order12:-} on hold.",
    ),
    (
        "callcentre",
        "en",
        "Account holder: {name:person_name}, account no {bank_account:bank_account}, branch IFSC {ifsc:ifsc|lower}.",
    ),
    # Hinglish chats
    (
        "chat",
        "hinglish",
        "Bhaiya mera PAN {pan:pan|lower} hai, aur mobile no. {mobile:mobile_in} pe OTP bhejo",
    ),
    ("chat", "hinglish", "Payment {upi_id:upi_id} pe kar diya, ref no {order12:-} hai"),
    (
        "chat",
        "hinglish",
        "Mera aadhaar {aadhaar:aadhaar|spaced} hai, address {address:address} pe courier bhejna",
    ),
    ("chat", "hinglish", "{name:person_name} ji ka number {mobile:mobile_in} hai, kal call karna"),
    ("chat", "hinglish", "Order {order12:-} kab aayega? Amount {amount:-} already pay kiya"),
    # Healthcare
    (
        "health",
        "en",
        "Patient name: {name:person_name}. ABHA {abha_number:abha_number}. ABHA address {abha_address:abha_address}. Contact {mobile:mobile_in|plus91}.",
    ),
    (
        "health",
        "en",
        "Discharge summary for Shri {name:person_name}, health ID {abha_number:abha_number}, admitted on {date:-}.",
    ),
    ("health", "hi", "मरीज़ का नाम: {name_hi:person_name}; आभा {abha_number:abha_number}"),
    # Bare records (no context)
    ("record", "en", "{pan:pan},{mobile:mobile_in},{email:email}"),
    ("record", "en", "{voter_epic:voter_epic}|{bank_account:bank_account}|{ifsc:ifsc}"),
    ("record", "en", "{aadhaar:aadhaar};{gstin:gstin};{card:card}"),
    ("record", "en", "{abha_number:abha_number},{abha_address:abha_address},{date:-}"),
    # Negatives (no PII at all)
    (
        "negative",
        "en",
        "Invoice {invoice:-} for Rs {amount:-} dated {date:-}; order no {order12:-}.",
    ),
    ("negative", "en", "Your OTP is {otp:-}. Transaction {txn:-} completed on {date:-}."),
    ("negative", "en", "Ticket {ticket:-} raised; tracking AWB {txn:-}; amount {amount:-}."),
    ("negative", "hinglish", "Kal ki meeting {date:-} ko hai, order {order12:-} ready rakhna"),
    ("negative", "hi", "बैठक {date:-} को होगी, राशि {amount:-}"),
]

SLOT = re.compile(r"\{(\w+):([\w-]+)(?:\|(\w+))?\}")


def render(template: str, record: dict[str, str], rng: random.Random) -> tuple[str, list[dict]]:
    text, spans, pos = [], [], 0
    last = 0
    for m in SLOT.finditer(template):
        literal = template[last : m.start()]
        text.append(literal)
        pos += len(literal)
        field, label, transform = m.groups()
        value = GENERATORS[field](rng) if field in GENERATORS else record[field]
        if transform:
            value = TRANSFORMS[transform](value)
        text.append(value)
        if label != "-":
            spans.append({"start": pos, "end": pos + len(value), "type": label})
        pos += len(value)
        last = m.end()
    text.append(template[last:])
    return "".join(text), spans


def generate(n: int, seed: int, split: str) -> list[dict]:
    rng = random.Random(seed)
    records = credgate.synth_indian_pii(n, seed=seed)
    docs = []
    for i, record in enumerate(records):
        category, lang, template = TEMPLATES[i % len(TEMPLATES)]
        text, spans = render(template, record, rng)
        docs.append(
            {
                "id": f"{split}-{i:04d}",
                "category": category,
                "lang": lang,
                "text": text,
                "spans": spans,
            }
        )
    rng.shuffle(docs)
    return docs


def main() -> None:
    out = Path(__file__).parent / "corpus"
    out.mkdir(exist_ok=True)
    for split, seed in (("dev", 101), ("test", 202)):
        docs = generate(700, seed, split)
        with open(out / f"{split}.jsonl", "w", encoding="utf-8") as f:
            for d in docs:
                f.write(json.dumps(d, ensure_ascii=False) + "\n")
        n_spans = sum(len(d["spans"]) for d in docs)
        print(f"{split}: {len(docs)} documents, {n_spans} labelled spans")


if __name__ == "__main__":
    main()
