import re

import pytest

import credgate
from credgate import Vault, redact, restore, tokenise


def test_tokenise_keeps_none_and_shape():
    vault = Vault()
    assert tokenise(["PAN ABCPE1234F", None, ""], vault) == ["PAN [PAN_1]", None, ""]
    assert tokenise("PAN ABCPE1234F", vault) == "PAN [PAN_1]"
    assert len(vault) == 1


def test_vault_methods_match_functions():
    vault = Vault()
    assert vault.tokenise("mobile 9876543210") == "mobile [MOBILE_IN_1]"
    assert vault.restore("call [MOBILE_IN_1]") == "call 9876543210"


def test_printing_a_vault_masks_values():
    vault = Vault()
    assert str(vault) == "Empty vault."
    vault.tokenise("Shri Ramesh Kumar, PAN ABCPE1234F")
    shown = str(vault) + repr(vault)
    assert "Ramesh" not in shown
    assert "ABCPE" not in shown
    assert "XXXXXX234F" in shown
    assert repr(vault) == "<credgate.Vault: 2 tokens>"
    revealed = vault.entries(reveal=True)
    assert [e["value"] for e in revealed] == ["Ramesh Kumar", "ABCPE1234F"]
    assert [e["token"] for e in vault.entries()] == ["[PERSON_NAME_1]", "[PAN_1]"]
    assert vault.entries()[0]["value"] == "XXXXXX XXXXX"


def test_vault_argument_is_checked():
    with pytest.raises(TypeError, match=r"credgate\.Vault"):
        tokenise("PAN ABCPE1234F", {})
    with pytest.raises(TypeError, match=r"credgate\.Vault"):
        restore("x", None)


def test_strict_restore_names_unknown_tokens():
    vault = Vault()
    vault.tokenise("PAN ABCPE1234F")
    with pytest.raises(credgate.UnknownTokenError, match=r"\[PAN_7\], \[pan_7\]"):
        restore("[PAN_1] [PAN_7] [pan_7]", vault, strict=True)


def test_tokenise_and_redact_replace_the_same_spans():
    text = "Name: Priya Nair; PAN: ABCPN1234K; UPI priya.n@oksbi"
    tokens = tokenise(text, Vault())
    assert re.sub(r"_[0-9]+\]", "]", tokens) == redact(text)
