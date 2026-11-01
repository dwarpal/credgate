"""Reversible tokenisation (the spec's "Tokenisation" rules)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import regex

from ._frames import texts
from .detect import Span, detect_pii, mask_value

# TYPE_n (numbered) or TYPE_<13 base32 characters> (keyed).
_NAME = r"[A-Za-z]+(?:_[A-Za-z]+)*_(?:[0-9]+|[A-Za-z2-7]{13})"
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


class TokenCollisionError(ValueError):
    """Two different values got the same keyed token (or the same token
    stands for different values in two vaults being merged)."""


# Keyed tokens (spec, "Keyed token id").
_TOKEN_DOMAIN = b"credgate-token-v1"
_KEY_CHECK = b"credgate-key-check-v1"
_MIN_KEY_BYTES = 32


def new_token_key() -> str:
    """A new random token key, as 64 hex digits. Keep it like a password:
    whoever holds it can check a guessed value against a token."""
    return secrets.token_hex(_MIN_KEY_BYTES)


def _token_key(
    key: str | bytes | None, env: str = "CREDGATE_TOKEN_KEY", what: str = "token key"
) -> bytes:
    if key is None:
        key = os.environ.get(env) or None
        if key is None:
            raise ValueError(f"No {what}: pass `key` or set {env}.")
    if isinstance(key, str):
        try:
            raw = bytes.fromhex(key.strip())
        except ValueError:
            raise ValueError(f"A {what} given as text must be hex digits.") from None
    elif isinstance(key, bytes):
        raw = key
    else:
        raise TypeError(f"A {what} must be hex text or bytes.")
    if len(raw) < _MIN_KEY_BYTES:
        raise ValueError(
            f"A {what} needs at least {_MIN_KEY_BYTES} bytes ({2 * _MIN_KEY_BYTES} hex "
            "digits); make one with new_token_key()."
        )
    return raw


def key_fingerprint(key: str | bytes | None = None) -> str:
    """16 hex digits that identify a token key without revealing it
    (``None`` uses ``CREDGATE_TOKEN_KEY``)."""
    return hmac.new(_token_key(key), _KEY_CHECK, hashlib.sha256).digest()[:8].hex()


def _keyed_id(key: bytes, type_: str, canonical: str) -> str:
    message = _TOKEN_DOMAIN + b"\0" + type_.encode() + b"\0" + canonical.encode()
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b32encode(mac[:8]).decode("ascii").rstrip("=").lower()


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

    Args:
        key: A token key (hex text or bytes, at least 32 bytes) for **keyed**
            tokens such as ``[PAN_4qzm7k2x9tbc3]``: the same identifier then
            gets the same token in every vault with this key - across
            sessions, datasets and parallel workers. Without a key, tokens
            are numbered (``[PAN_1]``) and belong to this vault only.
        keyed: Use keyed tokens with the key from ``CREDGATE_TOKEN_KEY``.
    """

    def __init__(self, key: str | bytes | None = None, *, keyed: bool = False) -> None:
        self._key = _token_key(key) if key is not None or keyed else None
        self._entries: list[_Entry] = []
        self._by_key: dict[tuple[str, str], _Entry] = {}
        self._by_token: dict[str, _Entry] = {}  # upper-cased token -> entry
        self._counts: dict[str, int] = {}

    @property
    def keyed(self) -> bool:
        """Whether this vault makes keyed tokens."""
        return self._key is not None

    @property
    def key_fingerprint(self) -> str | None:
        """The fingerprint of this vault's token key, or ``None`` if numbered."""
        return None if self._key is None else key_fingerprint(self._key)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        mode = "keyed" if self.keyed else "numbered"
        return f"<credgate.Vault: {len(self)} {mode} token{'s' if len(self) != 1 else ''}>"

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
            if self._key is None:
                n = self._counts.get(span.type, 0) + 1  # _add() records it
                token = f"[{span.type.upper()}_{n}]"
            else:
                token = f"[{span.type.upper()}_{_keyed_id(self._key, span.type, span.canonical)}]"
            entry = _Entry(token, span.type, span.data_class, span.canonical, span.value)
            self._add(entry)
        return entry.token

    def _add(self, entry: _Entry) -> None:
        other = self._by_token.get(entry.token.upper())
        if other is not None and (other.type, other.canonical) != (entry.type, entry.canonical):
            raise TokenCollisionError(
                f"Token {entry.token} would stand for two different values; "
                "use a different key, or keep these values in separate vaults."
            )
        self._entries.append(entry)
        self._by_key[(entry.type, entry.canonical)] = entry
        self._by_token[entry.token.upper()] = entry
        self._counts[entry.type] = self._counts.get(entry.type, 0) + 1

    def merge(self, other: Vault) -> Vault:
        """Add the entries of another keyed vault made with the same key (for
        example by a parallel worker). Returns this vault."""
        if not (self.keyed and other.keyed):
            raise ValueError(
                "Only keyed vaults can be merged: numbered tokens belong to one vault."
            )
        if self.key_fingerprint != other.key_fingerprint:
            raise ValueError("The vaults were made with different token keys.")
        for e in other._entries:
            mine = self._by_key.get((e.type, e.canonical))
            if mine is None:
                self._add(e)
            elif mine.token.upper() != e.token.upper():
                raise TokenCollisionError(f"{e.type} value has tokens {mine.token} and {e.token}.")
        return self

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
            "mode": "keyed" if self.keyed else "numbered",
            **({"key_fingerprint": self.key_fingerprint} if self.keyed else {}),
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
    def open(
        cls,
        path: str | os.PathLike[str],
        passphrase: str | None = None,
        key: str | bytes | None = None,
    ) -> Vault:
        """Open a vault saved with :meth:`save`. Tokenising with it continues
        its numbering, and :func:`restore` can put its values back.

        A keyed vault needs its token key again (``key``, else
        ``CREDGATE_TOKEN_KEY``); the key itself is never saved.
        """
        data = Path(path).read_bytes()
        payload = json.loads(_decrypt(data, _passphrase(passphrase, confirm=False)))
        if payload.get("format") != "credgate-vault" or payload.get("version") != 1:
            raise VaultFileError("Unsupported vault contents.")
        mode = payload.get("mode", "numbered")
        if mode == "keyed":
            vault = cls(key, keyed=True)
            if vault.key_fingerprint != payload.get("key_fingerprint"):
                raise VaultFileError(
                    "The token key does not match the one this vault was saved with."
                )
        elif mode == "numbered":
            if key is not None:
                raise VaultFileError("This vault has numbered tokens; it does not use a token key.")
            vault = cls()
        else:
            raise VaultFileError(f"Unsupported vault mode {mode!r}.")
        for e in payload["entries"]:
            vault._add(_Entry(e["token"], e["type"], e["class"], e["canonical"], e["value"]))
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
    text: str | Sequence[str | None] | Any,
    vault: Vault,
    detectors: Sequence[str] | None = None,
    context: str | Sequence[str | None] | None = None,
    min_confidence: float = 0.0,
) -> Any:
    """Replace every detected identifier with a numbered token such as ``[PAN_1]``.

    The vault records which value each token stands for, so
    :func:`restore` can put the values back into a model's answer. The same
    identifier gets the same token however it is written, across documents
    and across calls with the same vault.

    ``text`` can be a string, a sequence of strings, a pandas or Polars
    Series, or an Arrow array; the result has the same type. Missing values
    stay as they are.
    """
    if not isinstance(vault, Vault):
        raise TypeError("`vault` must be a credgate.Vault.")
    docs, _, wrap = texts(text)
    spans = detect_pii(docs, detectors, context, min_confidence)
    tokens = [vault._token_for(s) for s in spans]  # in document, then position order
    out = list(docs)
    for s, token in sorted(zip(spans, tokens, strict=True), key=lambda p: (p[0].doc, -p[0].start)):
        out[s.doc] = out[s.doc][: s.start] + token + out[s.doc][s.end :]
    return wrap(out)


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
        entry = vault._by_token.get(f"[{name}]".upper())
        if entry is not None:
            return entry.value
        if m.group("bracketed"):
            unknown.append(m.group(0))
        return m.group(0)

    out = _CANDIDATE.sub(replace, text)
    if strict and unknown:
        raise UnknownTokenError(f"Unknown token(s): {', '.join(unknown)}")
    return out
