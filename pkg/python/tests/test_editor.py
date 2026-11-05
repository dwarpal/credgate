"""The Python policy editor: roles and tabs, the signed-in user, the
detector form, and the page each role gets (needs Shiny for Python)."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("shiny")

from credgate.editor import _logic as L
from credgate.editor import policy_editor
from credgate.editor._app import editor_ui
from credgate.users import set_user


@pytest.fixture
def users(tmp_path):
    path = tmp_path / "users.yaml"
    set_user(path, "priya", role="admin")
    set_user(path, "meera", role="auditor")
    set_user(path, "arjun", role="user")
    set_user(path, "ravi", role="user", active=False)
    return path


def test_roles_come_from_the_users_file(users, tmp_path):
    assert L.editor_role(None, None) == "admin"  # no users file: everyone is an admin
    assert L.editor_role(users, "priya") == "admin"
    assert L.editor_role(users, "meera") == "auditor"
    assert L.editor_role(users, "arjun") == "user"
    assert L.editor_role(users, "ravi") is None  # a leaver
    assert L.editor_role(users, "nobody") is None
    assert L.editor_role(users, None) is None
    bad = tmp_path / "bad.yaml"
    bad.write_text("kind: something-else\n")
    assert L.editor_role(bad, "priya") is None  # an invalid file lets no one in


def test_signed_in_user_from_a_trusted_header():
    headers = {"x-auth-request-user": "  priya@bank.example "}
    assert L.header_user(headers, "X-Auth-Request-User") == "priya@bank.example"
    assert L.header_user(headers, None) is None
    assert L.header_user({"x-auth-request-user": "priya; drop"}, "X-Auth-Request-User") is None
    assert L.header_user({}, "X-Auth-Request-User") is None


def test_detector_form():
    det = L.detector_from_form(
        "staff_code", "financial", "", "EMP-[0-9]{5}", "staff, a/c", False, "Staff EMP-12345\n", ""
    )
    assert det["label"] == "staff_code"
    assert det["patterns"] == ["EMP-[0-9]{5}"]
    assert det["context"] == "staff|a/c"
    assert det["base_without_context"] == 0.4
    assert det["examples"] == {"match": ["Staff EMP-12345"]}
    req = L.detector_from_form("x", "financial", "X", "X[0-9]+", "a.b", True, "", "")
    assert req["context"] == r"a\.b"
    assert req["context_required"] is True
    assert req["base"] == 0.5
    assert "lower-case" in L.detector_from_form("Bad", "financial", "", "X", "", False, "", "")
    assert "pattern" in L.detector_from_form("x", "financial", "", "", "", False, "", "")
    assert "regular expression" in L.detector_from_form(
        "x", "financial", "", "(", "", False, "", ""
    )
    assert "keyword" in L.detector_from_form("x", "financial", "", "X", "", True, "", "")


def test_rename_and_file_names():
    rule = {"id": "r", "when": {"destinations": ["a", "b"]}, "action": "block"}
    assert L.rename_destination(rule, "a", "c")["when"]["destinations"] == ["c", "b"]
    assert rule["when"]["destinations"] == ["a", "b"]  # not changed in place
    assert L.new_detectors_file_name("bank-detectors.yaml") == "bank-detectors.yaml"
    assert L.new_detectors_file_name("../x.yaml") is None
    assert L.new_detectors_file_name("x.txt") is None


def _tabs(html: str) -> list[str]:
    return re.findall(r'data-value="([^"]+)"[^>]*role="tab"', html) or re.findall(
        r'role="tab"[^>]*data-value="([^"]+)"', html
    )


@pytest.mark.parametrize("role", ["admin", "auditor", "user"])
def test_each_role_gets_its_tabs_only(role, tmp_path):
    html = str(editor_ui(str(tmp_path / "bank.yaml"), role, "someone"))
    for tab in L.TABS["admin"]:
        shown = f'data-value="{tab}"' in html
        assert shown == (tab in L.TABS[role]), (role, tab)
    edits = ("id=\"save\"", "id=\"ep_apply\"", "id=\"rule_apply\"", "id=\"test_add\"",
             "id=\"det_save\"", "id=\"user_new_key\"", "id=\"try_min_confidence\"")  # fmt: skip
    for control in edits:
        assert (control in html) == (role == "admin"), (role, control)
    # users see no policy make-up: no summary boxes and no sidebar
    assert ('id="stats"' in html) == (role != "user")
    assert ("<aside" in html) == (role != "user")


def test_no_access_page(tmp_path):
    html = str(editor_ui(str(tmp_path / "bank.yaml"), None, "ravi"))
    assert "ravi has no access to this app" in html
    assert 'data-value="Try it"' not in html


def test_the_app_is_built(tmp_path, users):
    app = policy_editor(tmp_path / "bank.yaml", user="priya", users=users)
    assert type(app).__name__ == "App"
