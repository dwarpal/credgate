import pytest

import credgate
from credgate import TokenCollisionError, Vault
from credgate.tokenise import _Entry

KEY = "0123456789abcdef" * 4


def test_parallel_workers_merge_into_one_vault():
    rows = ["PAN ABCPE1234F", "mobile 9876543210", "PAN abcpe1234f again", "PAN AAACR5055K"]
    workers = [Vault(KEY) for _ in range(2)]
    out = workers[0].tokenise(rows[:2]) + workers[1].tokenise(rows[2:])
    merged = Vault(KEY).merge(workers[0]).merge(workers[1])
    assert len(merged) == 3
    assert credgate.tokenise(rows, Vault(KEY)) == out
    assert merged.restore(out[2]) == "PAN ABCPE1234F again"


def test_merge_refuses_numbered_or_other_keys():
    with pytest.raises(ValueError, match="Only keyed"):
        Vault(KEY).merge(Vault())
    with pytest.raises(ValueError, match="different token keys"):
        Vault(KEY).merge(Vault("ff" * 32))


def test_collisions_are_errors():
    vault = Vault(KEY)
    vault.tokenise("PAN ABCPE1234F")
    token = vault.entries()[0]["token"]
    other = Vault(KEY)
    other._add(_Entry(token.lower(), "pan", "identity_strong", "XYZPQ9876R", "XYZPQ9876R"))
    with pytest.raises(TokenCollisionError):
        vault.merge(other)


def test_key_from_environment_and_formats(monkeypatch):
    monkeypatch.setenv("CREDGATE_TOKEN_KEY", KEY)
    assert Vault(keyed=True).tokenise("PAN ABCPE1234F") == "PAN [PAN_bpg46o6x465d4]"
    assert credgate.key_fingerprint() == credgate.key_fingerprint(bytes.fromhex(KEY))
    assert Vault(bytes.fromhex(KEY)).tokenise("PAN ABCPE1234F") == "PAN [PAN_bpg46o6x465d4]"
    monkeypatch.delenv("CREDGATE_TOKEN_KEY")
    with pytest.raises(ValueError, match="No token key"):
        Vault(keyed=True)
    with pytest.raises(TypeError):
        Vault(42)


def test_vault_shows_its_mode_but_never_the_key():
    vault = Vault(KEY)
    assert repr(vault) == "<credgate.Vault: 0 keyed tokens>"
    assert repr(Vault()) == "<credgate.Vault: 0 numbered tokens>"
    vault.tokenise("PAN ABCPE1234F")
    assert KEY not in repr(vault) + str(vault)
    assert vault.keyed
    assert vault.key_fingerprint == "f6b1b6493c30fead"
    assert Vault().key_fingerprint is None


def test_new_keys_are_random_and_valid():
    a, b = credgate.new_token_key(), credgate.new_token_key()
    assert a != b
    assert len(a) == 64
    Vault(a)


def test_saved_keyed_vault_needs_its_key(tmp_path, monkeypatch):
    pytest.importorskip("nacl")
    monkeypatch.delenv("CREDGATE_TOKEN_KEY", raising=False)
    path = tmp_path / "v.cgvault"
    vault = Vault(KEY)
    vault.tokenise("PAN ABCPE1234F")
    vault.save(path, passphrase="a test passphrase")
    with pytest.raises(ValueError, match="No token key"):
        Vault.open(path, passphrase="a test passphrase")
    opened = Vault.open(path, passphrase="a test passphrase", key=KEY)
    assert opened.keyed
    assert opened.restore("[PAN_bpg46o6x465d4]") == "ABCPE1234F"
