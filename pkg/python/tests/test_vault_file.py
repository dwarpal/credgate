import stat

import pytest

from credgate import Vault, VaultFileError

pytest.importorskip("nacl")

PASS = "a test passphrase"


def test_saved_vault_opens_again_and_continues_numbering(tmp_path):
    path = tmp_path / "v.cgvault"
    vault = Vault()
    vault.tokenise("PAN ABCPE1234F, mobile 9876543210")
    vault.save(path, passphrase=PASS)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes()[:8] == b"CGVAULT\x01"
    opened = Vault.open(path, passphrase=PASS)
    assert opened.entries(reveal=True) == vault.entries(reveal=True)
    assert opened.tokenise("PAN XYZPQ9876R, abcpe1234f") == "PAN [PAN_2], [PAN_1]"
    assert opened.restore("[MOBILE_IN_1]") == "9876543210"


def test_each_save_uses_new_salt_and_nonce(tmp_path):
    vault = Vault()
    vault.tokenise("PAN ABCPE1234F")
    vault.save(tmp_path / "a.cgvault", passphrase=PASS)
    vault.save(tmp_path / "b.cgvault", passphrase=PASS)
    a, b = (tmp_path / "a.cgvault").read_bytes(), (tmp_path / "b.cgvault").read_bytes()
    assert a[9:65] != b[9:65]


def test_empty_vault_round_trips(tmp_path):
    path = tmp_path / "v.cgvault"
    Vault().save(path, passphrase=PASS)
    assert len(Vault.open(path, passphrase=PASS)) == 0


def test_passphrase_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDGATE_VAULT_PASSPHRASE", PASS)
    path = tmp_path / "v.cgvault"
    vault = Vault()
    vault.tokenise("PAN ABCPE1234F")
    vault.save(path)
    assert len(Vault.open(path)) == 1


def test_refusals(tmp_path, monkeypatch):
    monkeypatch.delenv("CREDGATE_VAULT_PASSPHRASE", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    path = tmp_path / "v.cgvault"
    vault = Vault()
    vault.tokenise("PAN ABCPE1234F")
    with pytest.raises(VaultFileError, match="at least 12"):
        vault.save(path, passphrase="short")
    with pytest.raises(VaultFileError, match="No passphrase"):
        vault.save(path)
    vault.save(path, passphrase=PASS)
    with pytest.raises(VaultFileError, match="Wrong passphrase"):
        Vault.open(path, passphrase="the wrong passphrase")

    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    damaged = tmp_path / "damaged.cgvault"
    damaged.write_bytes(bytes(data))
    with pytest.raises(VaultFileError, match="damaged or altered"):
        Vault.open(damaged, passphrase=PASS)
    data[7] = 9
    damaged.write_bytes(bytes(data))
    with pytest.raises(VaultFileError, match="version 9"):
        Vault.open(damaged, passphrase=PASS)

    other = tmp_path / "notes.txt"
    other.write_text("not a vault")
    with pytest.raises(VaultFileError, match="Not a credgate vault"):
        Vault.open(other, passphrase=PASS)
    with pytest.raises(VaultFileError, match="not replacing"):
        vault.save(other, passphrase=PASS)
    assert other.read_text() == "not a vault"
