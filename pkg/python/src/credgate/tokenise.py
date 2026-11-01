"""Reversible tokenisation (the spec's "Tokenisation" rules)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import regex

from .detect import Span, detect_pii, mask_value

_NAME = r"[A-Za-z]+(?:_[A-Za-z]+)*_[0-9]+"
_CANDIDATE = regex.compile(
    rf"\[\s*(?P<bracketed>{_NAME})\s*\]|(?<![\p{{L}}\p{{N}}_])(?P<bare>{_NAME})(?![\p{{L}}\p{{N}}_])",
    regex.IGNORECASE,
)


@dataclass(frozen=True)
class _Entry:
    token: str
    type: str
    data_class: str
    canonical: str
    value: str


class UnknownTokenError(ValueError):
    """Raised by a strict :func:`restore` when text holds tokens the vault does not know."""


class VaultFileError(ValueError):
    """Raised when a vault file cannot be opened or saved: wrong passphrase,
    damaged or altered file, or not a vault file."""


# Saved vault layout (spec, "Saved vaults").
_MAGIC = b"CGVAULT\x01"
_KDF_SCRYPT_INTERACTIVE = 1
_SALT_BYTES = 32
_NONCE_BYTES = 24
_HEADER_BYTES = len(_MAGIC) + 1 + _SALT_BYTES + _NONCE_BYTES
_MIN_PASSPHRASE = 12


def _nacl() -> Any:
    try:
        import nacl.exceptions
        import nacl.pwhash
        import nacl.secret
        import nacl.utils
    except ImportError:
        raise ImportError(
            "Saving and opening vaults needs PyNaCl: pip install 'credgate[vault]'"
        ) from None
    return nacl


def _passphrase(passphrase: str | None, confirm: bool) -> str:
    if passphrase is None:
        passphrase = os.environ.get("CREDGATE_VAULT_PASSPHRASE") or None
    if passphrase is None:
        if not sys.stdin.isatty():
            raise VaultFileError(
                "No passphrase: pass `passphrase` or set CREDGATE_VAULT_PASSPHRASE."
            )
        import getpass

        passphrase = getpass.getpass("Vault passphrase: ")
        if confirm and getpass.getpass("Repeat passphrase: ") != passphrase:
            raise VaultFileError("The passphrases do not match.")
    if len(passphrase) < _MIN_PASSPHRASE:
        raise VaultFileError(f"The passphrase must have at least {_MIN_PASSPHRASE} characters.")
    return passphrase


def _key(nacl: Any, passphrase: str, salt: bytes) -> bytes:
    scrypt = nacl.pwhash.scrypt
    return scrypt.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=scrypt.OPSLIMIT_INTERACTIVE,
        memlimit=scrypt.MEMLIMIT_INTERACTIVE,
    )


def _encrypt(
    payload: bytes, passphrase: str, salt: bytes | None = None, nonce: bytes | None = None
) -> bytes:
    nacl = _nacl()
    salt = salt if salt is not None else nacl.utils.random(_SALT_BYTES)
    nonce = nonce if nonce is not None else nacl.utils.random(_NONCE_BYTES)
    box = nacl.secret.SecretBox(_key(nacl, passphrase, salt))
    sealed = box.encrypt(payload, nonce).ciphertext
    return _MAGIC + bytes([_KDF_SCRYPT_INTERACTIVE]) + salt + nonce + sealed


def _decrypt(data: bytes, passphrase: str) -> bytes:
    nacl = _nacl()
    if len(data) < _HEADER_BYTES or data[:7] != _MAGIC[:7]:
        raise VaultFileError("Not a credgate vault file.")
    if data[7] != _MAGIC[7]:
        raise VaultFileError(f"Unsupported vault file version {data[7]}.")
    if data[8] != _KDF_SCRYPT_INTERACTIVE:
        raise VaultFileError(f"Unsupported key derivation {data[8]}.")
    salt = data[9 : 9 + _SALT_BYTES]
    nonce = data[9 + _SALT_BYTES : _HEADER_BYTES]
    box = nacl.secret.SecretBox(_key(nacl, passphrase, salt))
    try:
        return box.decrypt(data[_HEADER_BYTES:], nonce)
    except nacl.exceptions.CryptoError:
        raise VaultFileError("Wrong passphrase, or the file is damaged or altered.") from None


class Vault:
    """The mapping between tokens and the values they stand for.

    A vault starts empty and grows as :func:`tokenise` meets new
    identifiers; the same identifier always gets the same token. It lives in
    memory only. Printing it masks the values.
    """

    def __init__(self) -> None:
        self._entries: list[_Entry] = []
        self._by_key: dict[tuple[str, str], _Entry] = {}
        self._by_token: dict[str, _Entry] = {}
        self._counts: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"<credgate.Vault: {len(self)} token{'s' if len(self) != 1 else ''}>"

    def __str__(self) -> str:
        if not self._entries:
            return "Empty vault."
        width = max(len(e.token) for e in self._entries)
        lines = [f"Vault with {len(self)} token{'s' if len(self) != 1 else ''} (values masked):"]
        for e in self._entries:
            lines.append(f"  {e.token:<{width}}  {mask_value(e.value, e.data_class)}")
        return "\n".join(lines)

    def entries(self, reveal: bool = False) -> list[dict[str, Any]]:
        """The vault's entries in order of creation; values are masked unless ``reveal``."""
        return [
            {
                "token": e.token,
                "type": e.type,
                "class": e.data_class,
                "value": e.value if reveal else mask_value(e.value, e.data_class),
            }
            for e in self._entries
        ]

    def _token_for(self, span: Span) -> str:
        key = (span.type, span.canonical)
        entry = self._by_key.get(key)
        if entry is None:
            n = self._counts.get(span.type, 0) + 1
            self._counts[span.type] = n
            entry = _Entry(
                token=f"[{span.type.upper()}_{n}]",
                type=span.type,
                data_class=span.data_class,
                canonical=span.canonical,
                value=span.value,
            )
            self._entries.append(entry)
            self._by_key[key] = entry
            self._by_token[entry.token] = entry
        return entry.token

    def save(self, path: str | os.PathLike[str], passphrase: str | None = None) -> None:
        """Save the vault to an encrypted file, so its tokens can be restored later.

        The passphrase comes from ``passphrase``, else the environment variable
        ``CREDGATE_VAULT_PASSPHRASE``, else a prompt; it needs at least 12
        characters and is never stored. Without it the file cannot be opened.
        The file is written readable only by you; an existing file is
        replaced only if it is itself a vault file.
        """
        path = Path(path)
        if path.exists():
            with path.open("rb") as f:
                if f.read(7) != _MAGIC[:7]:
                    raise VaultFileError(
                        f"{path} exists and is not a vault file; not replacing it."
                    )
        payload = {
            "format": "credgate-vault",
            "version": 1,
            "saved_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "entries": [
                {
                    "token": e.token,
                    "type": e.type,
                    "class": e.data_class,
                    "canonical": e.canonical,
                    "value": e.value,
                }
                for e in self._entries
            ],
        }
        data = _encrypt(
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            _passphrase(passphrase, confirm=not path.exists()),
        )
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    @classmethod
    def open(cls, path: str | os.PathLike[str], passphrase: str | None = None) -> Vault:
        """Open a vault saved with :meth:`save`. Tokenising with it continues
        its numbering, and :func:`restore` can put its values back."""
        data = Path(path).read_bytes()
        payload = json.loads(_decrypt(data, _passphrase(passphrase, confirm=False)))
        if payload.get("format") != "credgate-vault" or payload.get("version") != 1:
            raise VaultFileError("Unsupported vault contents.")
        vault = cls()
        for e in payload["entries"]:
            entry = _Entry(e["token"], e["type"], e["class"], e["canonical"], e["value"])
            vault._entries.append(entry)
            vault._by_key[(entry.type, entry.canonical)] = entry
            vault._by_token[entry.token] = entry
            vault._counts[entry.type] = vault._counts.get(entry.type, 0) + 1
        return vault

    def tokenise(
        self,
        text: str | Sequence[str | None],
        detectors: Sequence[str] | None = None,
        context: str | Sequence[str | None] | None = None,
        min_confidence: float = 0.0,
    ) -> str | list[str | None]:
        """Same as :func:`tokenise` with this vault."""
        return tokenise(text, self, detectors, context, min_confidence)

    def restore(self, text: str, strict: bool = False) -> str:
        """Same as :func:`restore` with this vault."""
        return restore(text, self, strict)


def tokenise(
    text: str | Sequence[str | None],
    vault: Vault,
    detectors: Sequence[str] | None = None,
    context: str | Sequence[str | None] | None = None,
    min_confidence: float = 0.0,
) -> str | list[str | None]:
    """Replace every detected identifier with a numbered token such as ``[PAN_1]``.

    The vault records which value each token stands for, so
    :func:`restore` can put the values back into a model's answer. The same
    identifier gets the same token however it is written, across documents
    and across calls with the same vault.

    Returns a string for a string input, otherwise a list of the same length
    (``None`` stays ``None``).
    """
    if not isinstance(vault, Vault):
        raise TypeError("`vault` must be a credgate.Vault.")
    single = isinstance(text, str)
    items = [text] if single else list(text)
    docs = ["" if t is None else t for t in items]
    spans = detect_pii(docs, detectors, context, min_confidence)
    tokens = [vault._token_for(s) for s in spans]  # in document, then position order
    out = list(docs)
    for s, token in sorted(zip(spans, tokens, strict=True), key=lambda p: (p[0].doc, -p[0].start)):
        out[s.doc] = out[s.doc][: s.start] + token + out[s.doc][s.end :]
    if single:
        return out[0]
    return [None if orig is None else t for orig, t in zip(items, out, strict=True)]


def restore(text: str, vault: Vault, strict: bool = False) -> str:
    """Put the values behind tokens back into text, such as a model's answer.

    Tokens are recognised with any letter case, with spaces inside the
    brackets (``[ pan_1 ]``) and without brackets (``PAN_1``). Tokens the
    vault does not know are left unchanged; with ``strict``, a bracketed
    unknown token (one the model invented or altered) raises
    :class:`UnknownTokenError`.
    """
    if not isinstance(vault, Vault):
        raise TypeError("`vault` must be a credgate.Vault.")
    unknown: list[str] = []

    def replace(m: regex.Match[str]) -> str:
        name = m.group("bracketed") or m.group("bare")
        entry = vault._by_token.get(f"[{name.upper()}]")
        if entry is not None:
            return entry.value
        if m.group("bracketed"):
            unknown.append(m.group(0))
        return m.group(0)

    out = _CANDIDATE.sub(replace, text)
    if strict and unknown:
        raise UnknownTokenError(f"Unknown token(s): {', '.join(unknown)}")
    return out
