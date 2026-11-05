"""The policy editor as a Shiny for Python app: the same tabs, roles and
behaviour as the R editor (``credgate::policy_editor()``), on the same files."""

from __future__ import annotations

import copy
import getpass
import os
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from htmltools import HTML, Tag, TagChild, TagList, tags
from shiny import App, reactive, render, req, ui

from .. import proxy_keys as _keys
from ..audit import own_activity
from ..custom import CLASSES, _compile_file
from ..detect import _detect_with, explain_pii, mask_value
from ..detectors import builtin_detectors
from ..policy import Policy
from ..policy_tests import run_policy_tests, test_from_decision, tests_path, write_policy_tests
from ..policy_write import policy_changes, policy_diff, write_policy
from ..users import read_users
from . import _logic as L

BADGE_HELP = {
    "local": "On the analyst's own machine",
    "internal": "Models the organisation runs itself",
    "frontier": "External providers: the data leaves the organisation",
    "allow": "Sent as is",
    "redact": "Replaced by a label such as [PAN]",
    "tokenise": "Replaced by a reversible token kept in the vault",
    "block": "The whole request is refused",
    "blocked": "Every request to this endpoint is refused",
}
DOT = "·"
_SHIELD = (
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'
)
# Bootstrap's primary colour as in the R editor's theme (bslib there).
_THEME = """
:root, [data-bs-theme="light"] { --bs-primary: #0e5a6b; --bs-primary-rgb: 14, 90, 107;
  --bs-link-color: #0e5a6b; --bs-link-color-rgb: 14, 90, 107; --bs-border-radius: 8px; }
.btn-primary { --bs-btn-bg: #0e5a6b; --bs-btn-border-color: #0e5a6b;
  --bs-btn-hover-bg: #0b4856; --bs-btn-hover-border-color: #0b4856;
  --bs-btn-active-bg: #0b4856; --bs-btn-disabled-bg: #0e5a6b;
  --bs-btn-disabled-border-color: #0e5a6b; }
.btn-outline-primary { --bs-btn-color: #0e5a6b; --bs-btn-border-color: #0e5a6b;
  --bs-btn-hover-bg: #0e5a6b; --bs-btn-hover-border-color: #0e5a6b; --bs-btn-active-bg: #0e5a6b; }
.cg-topbar { display: flex; align-items: center; padding: .6rem 1rem; background: var(--cg-surface);
  border-bottom: 1px solid var(--cg-line); margin: 0 -12px 1rem; }
"""


def badge(text: str, kind: str, title: str | None = None) -> Tag:
    return tags.span(text, class_=f"cg-badge cg-{kind}", title=title or BADGE_HELP.get(kind))


def tip(label: str, text: str) -> Tag:
    """A label with an info icon that explains it on hover or focus."""
    icon = tags.span("i", class_="cg-tip", tabindex="0", **{"aria-label": text})
    return tags.span(label, ui.tooltip(icon, text, placement="right"))


def confidence_bar(x: float) -> Tag:
    bar = tags.span(tags.span(style=f"width:{round(100 * x)}%"), class_="bar")
    return tags.span(bar, f"{x:.2f}", class_="cg-conf")


def why_list(reasons: str) -> list[Tag]:
    return [tags.div(r) for r in reasons.split("; ")]


def table(head: list[str], rows: list[Tag]) -> Tag:
    return tags.div(
        tags.table(
            tags.thead(tags.tr(*[tags.th(h) for h in head])), tags.tbody(*rows), class_="cg-table"
        ),
        class_="cg-scroll",
    )


def empty(text: str) -> Tag:
    return tags.div(text, class_="cg-empty")


def highlight(line: str, spans: list[Any]) -> list[TagChild]:
    """A line with the given spans highlighted."""
    out: list[TagChild] = []
    at = 0
    for s in sorted(spans, key=lambda s: s.start):
        if s.start < at:
            continue
        if s.start > at:
            out.append(line[at : s.start])
        out.append(tags.mark(line[s.start : s.end], title=s.type))
        at = s.end
    if at < len(line):
        out.append(line[at:])
    return out


def _who(user: str | None, headers: Any, trust_header: str | None, shiny_user: Any) -> str | None:
    return (
        user
        or (shiny_user if isinstance(shiny_user, str) else None)
        or L.header_user(headers, trust_header)
    )


# --- the page --------------------------------------------------------------------


def _header(with_status: bool = True) -> Tag:
    return tags.div(
        HTML(_SHIELD),
        tags.span("credgate", class_="cg-name"),
        tags.span("Policy editor", class_="cg-sub"),
        ui.output_ui("header_status", class_="cg-header-status") if with_status else None,
        ui.input_dark_mode(id="dark_mode"),
        class_="cg-brand",
    )


def _head() -> TagList:
    return TagList(
        ui.include_css(L.asset("editor.css"), method="inline"),
        ui.include_js(L.asset("editor.js"), method="inline"),
        tags.style(_THEME),
    )


def _sidebar(path: str, can_edit: bool) -> Any:
    section = lambda x: tags.div(x, class_="cg-section")  # noqa: E731
    admin = tags.div(
        section("Policy"),
        ui.input_text(
            "policy_id",
            tip(
                "Policy id",
                "A short name for this policy. It is recorded with every decision in the "
                "audit log, together with the revision.",
            ),
        ),
        ui.input_text_area("description", "Description", rows=3),
        ui.input_select(
            "default_action",
            tip(
                "When no rule matches",
                "What happens to an identifier that no rule matches. block is the safest: "
                "anything not explicitly allowed stops the request.",
            ),
            list(L.ACTIONS),
        ),
        ui.input_numeric(
            "min_confidence",
            tip(
                "Minimum confidence (0-1)",
                "Matches scored below this are ignored. For example, an order number that "
                "passes the Aadhaar checksum by chance scores about 0.42.",
            ),
            0.5,
            min=0,
            max=1,
            step=0.05,
        ),
        section("Save"),
        ui.input_text(
            "user",
            tip(
                "Your name",
                "Recorded in the change log with every save. Behind single sign-on it is "
                "filled in from the signed-in user.",
            ),
        ),
        ui.input_text(
            "note",
            tip(
                "Why this change",
                "A few words for the change log, such as a ticket number or an approval. "
                "Reviewers and auditors read it.",
            ),
            placeholder="e.g. new GPU endpoint approved",
        ),
        ui.output_ui("save_anyway_ui"),
        ui.tooltip(
            ui.input_action_button("save", "Save new revision", class_="btn-primary"),
            "Writes the policy with its revision raised by one and adds an entry to the change "
            "log. Only possible when the draft is valid and has changes.",
        ),
        ui.tooltip(
            ui.input_action_button("reload", "Discard changes", class_="btn-link btn-sm"),
            "Throws away the draft and reloads the saved file.",
        ),
        id="cg-admin-controls",
    )
    return ui.sidebar(
        section("Policy file"),
        tags.div(path, class_="cg-file"),
        ui.output_ui("status"),
        ui.output_ui("role_note"),
        admin if can_edit else None,
        width=320,
    )


def _tabs(path: str, role: str) -> Any:
    can_edit = role == "admin"
    actions = lambda *x: tags.div(*x, class_="cg-actions")  # noqa: E731
    row = lambda *x: tags.div(*x, class_="cg-actions cg-field-row")  # noqa: E731
    panels: dict[str, Any] = {}
    panels["Endpoints"] = ui.nav_panel(
        "Endpoints",
        tags.p(
            "The model endpoints requests may go to. An endpoint not listed here receives "
            "nothing. Click a row to edit it.",
            class_="cg-lede",
        ),
        ui.output_ui("endpoints"),
        tags.div(
            ui.output_ui("ep_form_title", inline=True),
            ui.layout_columns(
                ui.input_select(
                    "ep_pick",
                    tip(
                        "Endpoint",
                        "Pick an endpoint to edit, or (new endpoint) to add one. You can also "
                        "click a row in the table.",
                    ),
                    {"": "(new endpoint)"},
                ),
                ui.input_text(
                    "ep_name",
                    tip(
                        "Name",
                        "How people and rules refer to this endpoint, e.g. claude or vllm-gpu. "
                        "Renaming it updates the rules that name it.",
                    ),
                ),
                ui.input_select(
                    "ep_tier",
                    tip(
                        "Tier",
                        "Where the data ends up. local: the analyst's own machine. internal: "
                        "models the organisation runs itself. frontier: external providers, "
                        "also when reached through its own gateway.",
                    ),
                    list(L.TIERS),
                ),
                ui.input_text(
                    "ep_provider",
                    tip(
                        "Provider",
                        "Who runs the model (ollama, vllm, anthropic...). For the record only; "
                        "rules do not use it.",
                    ),
                    placeholder="vllm, anthropic...",
                ),
                col_widths=(3, 3, 3, 3),
            ),
            ui.layout_columns(
                ui.input_text(
                    "ep_url",
                    tip("URL", "The OpenAI-compatible base URL the proxy forwards requests to."),
                    placeholder="https://llm.bank.internal/v1",
                ),
                ui.input_text(
                    "ep_description",
                    tip(
                        "Description",
                        "Why this endpoint exists or what it may be used for. Kept in the "
                        "policy file.",
                    ),
                ),
                tags.div(
                    ui.input_checkbox(
                        "ep_blocked",
                        tip(
                            "Blocked",
                            "Keeps the endpoint on record but refuses every request to it, "
                            "e.g. a tool not yet approved.",
                        ),
                    ),
                    style="padding-top: 1.9rem",
                ),
                col_widths=(5, 5, 2),
            ),
            actions(
                ui.tooltip(
                    ui.input_action_button(
                        "ep_apply", "Apply to draft", class_="btn-primary btn-sm"
                    ),
                    "Adds or updates the endpoint in the draft. Nothing is written until you save.",
                ),
                ui.tooltip(
                    ui.input_action_button(
                        "ep_delete", "Remove endpoint", class_="btn-outline-danger btn-sm"
                    ),
                    "Removes the endpoint from the draft. Not allowed while a rule names it.",
                ),
            )
            if can_edit
            else None,
            class_="cg-form",
        ),
    )
    panels["Rules"] = ui.nav_panel(
        "Rules",
        tags.p(
            "Checked in order for each identifier found: the first rule that matches decides "
            "what happens to it. Any block stops the whole request. Click a rule to edit or "
            "move it.",
            class_="cg-lede",
        ),
        ui.output_ui("rules"),
        tags.div(
            ui.output_ui("rule_form_title", inline=True),
            ui.layout_columns(
                ui.input_select(
                    "rule_pick",
                    tip(
                        "Rule",
                        "Pick a rule to edit, or (new rule) to add one at the end. You can also "
                        "click a rule in the list.",
                    ),
                    {"": "(new rule)"},
                ),
                ui.input_text(
                    "rule_id",
                    tip(
                        "Rule id",
                        "A short unique name. Decisions and the audit log name the rule that "
                        "decided each action.",
                    ),
                ),
                ui.input_select(
                    "rule_action",
                    tip(
                        "Action",
                        "allow: sent as is. redact: replaced by a label like [PAN]. tokenise: "
                        "replaced by a reversible token kept in the vault. block: the whole "
                        "request is refused.",
                    ),
                    list(L.ACTIONS),
                ),
                ui.input_text(
                    "rule_description",
                    tip(
                        "Description",
                        "Why the rule exists, e.g. the regulation or approval behind it. Kept "
                        "in the policy file.",
                    ),
                ),
                col_widths=(3, 3, 2, 4),
            ),
            ui.layout_columns(
                ui.input_selectize(
                    "rule_destinations",
                    tip("Endpoints", "Only requests to these endpoints. Empty: any endpoint."),
                    [],
                    multiple=True,
                ),
                ui.input_selectize(
                    "rule_tiers",
                    tip("Tiers", "Only requests to endpoints of these tiers. Empty: any tier."),
                    list(L.TIERS),
                    multiple=True,
                ),
                ui.input_selectize(
                    "rule_classes",
                    tip(
                        "Data classes",
                        "Groups of identifier types, e.g. financial covers card numbers and "
                        "bank accounts. Empty: any class.",
                    ),
                    [],
                    multiple=True,
                ),
                col_widths=(4, 4, 4),
            ),
            ui.layout_columns(
                ui.input_selectize(
                    "rule_types",
                    tip(
                        "Identifier types",
                        "Particular identifiers, e.g. pan, aadhaar, card_cvv. Empty: any type.",
                    ),
                    [],
                    multiple=True,
                ),
                ui.input_selectize(
                    "rule_all_of",
                    tip(
                        "Only when all of these are present",
                        "The rule applies only if the request contains every one of these "
                        "types, e.g. card, card_cvv and card_expiry together.",
                    ),
                    [],
                    multiple=True,
                ),
                col_widths=(6, 6),
            ),
            tags.p("Empty fields match everything. Conditions combine with AND.", class_="cg-hint"),
            actions(
                ui.tooltip(
                    ui.input_action_button(
                        "rule_apply", "Apply to draft", class_="btn-primary btn-sm"
                    ),
                    "Adds the rule at the end, or updates the selected one. Nothing is written "
                    "until you save.",
                ),
                ui.tooltip(
                    ui.input_action_button(
                        "rule_up", "↑ Move up", class_="btn-outline-secondary btn-sm"
                    ),
                    "Checked earlier. The first matching rule decides, so order changes outcomes.",
                ),
                ui.tooltip(
                    ui.input_action_button(
                        "rule_down", "↓ Move down", class_="btn-outline-secondary btn-sm"
                    ),
                    "Checked later. Use Try it to see the effect.",
                ),
                ui.tooltip(
                    ui.input_action_button(
                        "rule_delete", "Remove rule", class_="btn-outline-danger btn-sm"
                    ),
                    "Removes the selected rule from the draft.",
                ),
            )
            if can_edit
            else None,
            class_="cg-form",
        ),
    )
    panels["Try it"] = ui.nav_panel(
        "Try it",
        tags.p(
            "What the policy does with a request: allowed or blocked, and what happens to each "
            "identifier (for admins, the draft before saving). Nothing typed here is stored or "
            "logged.",
            class_="cg-lede",
        ),
        ui.layout_columns(
            tags.div(
                ui.input_text_area(
                    "try_text",
                    "Request text",
                    width="100%",
                    rows=6,
                    value="Customer PAN ABCPE1234F, mobile +91 98765 43210. "
                    "Card 4111 1111 1111 1111, CVV 123, expiry 08/29.",
                ),
                ui.input_select(
                    "try_endpoint",
                    tip(
                        "Sent to",
                        "The endpoint the request would go to. Its tier and name decide which "
                        "rules apply.",
                    ),
                    [],
                    width="100%",
                ),
                row(
                    ui.input_text(
                        "test_id",
                        tip(
                            "Test id", "A short name for the test, such as card-blocked-for-claude."
                        ),
                        placeholder="e.g. card-blocked-for-claude",
                    ),
                    ui.tooltip(
                        ui.input_action_button(
                            "test_add", "Save as a test", class_="btn-outline-primary btn-sm"
                        ),
                        "Check the decision is right first. Adds this text, endpoint and decision "
                        "to the tests file beside the policy, so every later change must keep it.",
                    ),
                )
                if can_edit
                else None,
            ),
            tags.div(ui.output_ui("try_result"), ui.output_ui("try_output")),
            col_widths=(5, 7),
        ),
        ui.input_slider(
            "try_min_confidence",
            tip(
                "Minimum confidence",
                "The same setting as in the sidebar: matches scored below it are ignored. Drag it "
                "to see what would be caught or let through; it changes the draft.",
            ),
            min=0,
            max=1,
            value=0.5,
            step=0.05,
            width="100%",
        )
        if can_edit
        else None,
        ui.output_ui("try_matches"),
        ui.output_ui("try_misses"),
    )
    panels["Tests"] = ui.nav_panel(
        "Tests",
        tags.p(
            "Requests and what the policy must do with them, from ",
            tags.code(tests_path(path).name),
            " beside the policy. They run against the draft on every change; ",
            tags.code("credgate policy test"),
            " runs them in CI.",
            class_="cg-lede",
        ),
        ui.output_ui("tests_table"),
        row(
            ui.input_select("test_pick", "Test", []),
            ui.tooltip(
                ui.input_action_button(
                    "test_delete", "Remove test", class_="btn-outline-danger btn-sm"
                ),
                "Removes the test from the tests file at once.",
            ),
        )
        if can_edit
        else None,
    )
    panels["Detectors"] = ui.nav_panel(
        "Detectors",
        tags.p(
            "Your own detectors (loan account numbers, customer ids, staff codes) in a custom "
            "detectors file named in the policy. Edit the file, try it on a sample, and save: "
            "the examples are checked first, as on every load. Use synthetic data only.",
            class_="cg-lede",
        ),
        ui.layout_columns(
            tags.div(
                ui.input_select(
                    "det_file",
                    tip(
                        "File",
                        "The custom detectors files the policy names, or a new one beside the "
                        "policy (added to the policy's detectors list).",
                    ),
                    {"": "(new file)"},
                    width="100%",
                ),
                ui.output_ui("det_new_name"),
                ui.accordion(
                    ui.accordion_panel(
                        "Add a detector from a form",
                        ui.input_text(
                            "gen_id",
                            tip(
                                "Id",
                                "Lower-case letters, digits and _, e.g. loan_account. Reported "
                                "as the type, and used in rules.",
                            ),
                            placeholder="loan_account",
                        ),
                        ui.input_select(
                            "gen_class",
                            tip(
                                "Class",
                                "The group that policy rules can name, e.g. financial. One of "
                                "the seven classes credgate knows.",
                            ),
                            list(CLASSES),
                            selected="financial",
                        ),
                        ui.input_text("gen_label", "Label", placeholder="Loan account number"),
                        ui.input_text(
                            "gen_pattern",
                            tip(
                                "Pattern (regex)",
                                "What the value looks like, e.g. LN[0-9]{10} for LN and ten "
                                "digits. It is not matched inside a longer word or number.",
                            ),
                            placeholder="LN[0-9]{10}",
                        ),
                        ui.input_text(
                            "gen_keywords",
                            tip(
                                "Keywords nearby (comma-separated)",
                                "Words that, near a value, make it more certain, e.g. loan, a/c. "
                                "Taken literally.",
                            ),
                            placeholder="loan, a/c",
                        ),
                        ui.input_checkbox("gen_required", "Report only with a keyword nearby"),
                        ui.input_text_area(
                            "gen_match",
                            tip(
                                "Should match (one per line)",
                                "Examples that must be found. They are checked every time the "
                                "file loads.",
                            ),
                            rows=2,
                            placeholder="Loan a/c LN0012345678",
                        ),
                        ui.input_text_area(
                            "gen_no_match",
                            tip(
                                "Should not match (one per line)",
                                "Examples that must not be found, such as a near-miss you want "
                                "ignored.",
                            ),
                            rows=2,
                            placeholder="LN00123",
                        ),
                        ui.tooltip(
                            ui.input_action_button(
                                "gen_add", "Add to the file", class_="btn-outline-primary btn-sm"
                            ),
                            "Adds the detector to the YAML below (not saved yet). The file is "
                            "rewritten in a standard layout, so comments in it are not kept.",
                        ),
                    ),
                    open=False,
                ),
                ui.input_text_area(
                    "det_yaml", "Detectors (YAML)", rows=18, width="100%", resize="vertical"
                ),
                actions(
                    ui.tooltip(
                        ui.input_action_button(
                            "det_save", "Save detectors file", class_="btn-primary btn-sm"
                        ),
                        "Checks the file as credgate loads it - every example must hold - then "
                        "writes it and loads it here. Save a new policy revision afterwards so the "
                        "audit log shows the change.",
                    )
                    if can_edit
                    else None,
                    ui.tooltip(
                        ui.input_action_button(
                            "det_revert", "Discard edits", class_="btn-link btn-sm"
                        ),
                        "Reloads the file as saved.",
                    ),
                ),
            ),
            tags.div(
                ui.output_ui("det_status"),
                ui.input_text_area(
                    "det_sample",
                    tip("Sample text", "Text to try the detectors on, one request per line."),
                    rows=5,
                    width="100%",
                    value="Loan a/c LN0012345678 overdue\nRef LN00123 is not an account",
                ),
                ui.output_ui("det_matches"),
                ui.output_ui("det_examples"),
            ),
            col_widths={"sm": 12, "xl": (5, 7)},
        ),
    )
    panels["My key"] = ui.nav_panel(
        "My key",
        tags.p(
            "Your key for the credgate proxy. Put it where your tool takes an API key (for "
            "Claude Code ANTHROPIC_API_KEY, for the OpenAI SDK api_key) and point the tool at the "
            "proxy. It is shown once, when it is made: keep it like a password.",
            class_="cg-lede",
        ),
        ui.output_ui("my_key"),
    )
    panels["My activity"] = ui.nav_panel(
        "My activity",
        tags.p(
            "Your own recent requests through the proxy: where they went, and whether they were "
            "allowed or blocked and why. Never their content.",
            class_="cg-lede",
        ),
        ui.output_ui("my_activity"),
    )
    panels["Users"] = ui.nav_panel(
        "Users",
        tags.p(
            "Everyone in the users file, their role, and their proxy key. Roles are changed on "
            "the server (credgate users ...); keys here.",
            class_="cg-lede",
        ),
        ui.output_ui("users_table"),
        tags.div(
            ui.input_select("user_pick", "User", []),
            ui.input_select(
                "user_days",
                tip(
                    "Valid for",
                    "How long the new key works. The longest allowed is set on the server "
                    "(key_max_days).",
                ),
                [],
            ),
            ui.tooltip(
                ui.input_action_button(
                    "user_new_key", "New key", class_="btn-outline-primary btn-sm"
                ),
                "Makes a key for this user (their old one stops working) and shows it once, for "
                "you to hand over.",
            ),
            ui.tooltip(
                ui.input_action_button(
                    "user_remove_key", "Remove key", class_="btn-outline-danger btn-sm"
                ),
                "Their key stops working at the proxy's next reload.",
            ),
            id="cg-user-actions",
            class_="cg-actions cg-field-row",
        )
        if can_edit
        else None,
        tags.h6("Access log", class_="cg-section"),
        ui.output_ui("access_log"),
    )
    panels["Changes"] = ui.nav_panel(
        "Changes",
        tags.h6("Since the last save", class_="cg-section") if role != "user" else None,
        ui.output_ui("pending") if role != "user" else None,
        tags.h6("Change log", class_="cg-section"),
        ui.output_ui("history"),
    )
    return ui.navset_card_tab(*[panels[t] for t in L.TABS[role]], id="tabs")


def editor_ui(path: str, role: str | None, who: str | None) -> Any:
    """The page for one person: their role's tabs only."""
    if role is None:
        message = (
            "You are not signed in."
            if who is None
            else (f"{who} has no access to this app. Ask your InfoSec team.")
        )
        return ui.page_fluid(
            _head(),
            tags.div(_header(with_status=False), class_="cg-topbar"),
            tags.div(tags.h4("No access"), tags.p(message), class_="cg-alert", id="cg-no-access"),
            title="credgate policy editor",
        )
    tabs = _tabs(path, role)
    if role == "user":
        # Users see their tabs only: not the policy's make-up, nor the sidebar
        # with the policy file and its status.
        return ui.page_fluid(
            _head(),
            tags.div(_header(), class_="cg-topbar"),
            tabs,
            title="credgate policy editor",
        )
    return ui.page_sidebar(
        _sidebar(path, role == "admin"),
        _head(),
        ui.output_ui("stats", class_="cg-stats"),
        tabs,
        title=_header(),
        window_title="credgate policy editor",
        fillable=False,
    )


# --- the server --------------------------------------------------------------------


def make_app(
    path: str | os.PathLike[str],
    user: str | None = None,
    users: str | os.PathLike[str] | None = None,
    keys: str | os.PathLike[str] | None = None,
    audit: str | os.PathLike[str] | None = None,
    trust_header: str | None = None,
) -> App:
    path = str(Path(path))
    base = str(Path(path).parent)

    def page(request: Any) -> Any:
        who = _who(user, request.headers, trust_header, None)
        return editor_ui(path, L.editor_role(users, who), who)

    def server(input: Any, output: Any, session: Any) -> None:
        headers = getattr(getattr(session, "http_conn", None), "headers", None)
        signed_in = _who(user, headers, trust_header, getattr(session, "user", None))
        role = L.editor_role(users, signed_in)
        if role is None:
            return
        can_edit = role == "admin"
        who = signed_in or getpass.getuser()
        me = who

        saved: reactive.Value[dict[str, Any]] = reactive.value(L.read_draft(path))
        draft: reactive.Value[dict[str, Any]] = reactive.value(L.read_draft(path))
        saved_at = reactive.value(0)
        det_saved_at = reactive.value(0)
        keys_changed = reactive.value(0)
        builtin = builtin_detectors()
        builtin_ids = {d.id for d in builtin}

        def edit(f: Any) -> None:
            if can_edit:
                draft.set(f(copy.deepcopy(draft.get())))

        def load_fields(x: dict[str, Any]) -> None:
            if not can_edit:
                return
            ui.update_text("policy_id", value=x.get("id") or "")
            ui.update_text_area("description", value=x.get("description") or "")
            ui.update_select("default_action", selected=x.get("default_action"))
            ui.update_numeric("min_confidence", value=x.get("min_confidence") or 0)

        @reactive.effect
        def _start() -> None:
            with reactive.isolate():
                load_fields(draft.get())
                if can_edit:
                    ui.update_text("user", value=who)
                    v = draft.get().get("min_confidence") or 0
                    ui.update_slider("try_min_confidence", value=v)

        # --- policy fields (admins) ---------------------------------------------------
        if can_edit:

            @reactive.effect
            @reactive.event(input.policy_id, ignore_init=True)
            def _id() -> None:
                edit(lambda x: {**x, "id": input.policy_id()})

            @reactive.effect
            @reactive.event(input.description, ignore_init=True)
            def _description() -> None:
                def f(x: dict[str, Any]) -> dict[str, Any]:
                    x.pop("description", None)
                    if input.description():
                        x["description"] = input.description()
                    return x

                edit(f)

            @reactive.effect
            @reactive.event(input.default_action, ignore_init=True)
            def _default() -> None:
                edit(lambda x: {**x, "default_action": input.default_action()})

            @reactive.effect
            @reactive.event(input.min_confidence, ignore_init=True)
            def _min() -> None:
                v = input.min_confidence()
                if v is None:
                    return

                def f(x: dict[str, Any]) -> dict[str, Any]:
                    if not (x.get("min_confidence") is None and float(v) == 0):
                        x["min_confidence"] = v
                    return x

                edit(f)
                if float(input.try_min_confidence()) != float(v):
                    ui.update_slider("try_min_confidence", value=v)

            @reactive.effect
            @reactive.event(input.try_min_confidence, ignore_init=True)
            def _slider() -> None:
                v = input.try_min_confidence()
                if float(v) != float(draft.get().get("min_confidence") or 0):
                    ui.update_numeric("min_confidence", value=v)

        @reactive.calc
        def problem() -> str | None:
            det_saved_at.get()  # a saved detectors file can make the policy valid
            return L.policy_problem(draft.get(), base)

        @reactive.calc
        def compiled() -> Policy | None:
            if problem() is not None:
                return None
            return Policy.from_dict(draft.get(), base=base)

        @reactive.calc
        def changes() -> list[str]:
            x = {**draft.get(), "revision": saved.get().get("revision")}
            try:
                return policy_diff(saved.get(), x)
            except Exception:
                return ["(the draft cannot be compared)"]

        @render.ui
        def role_note() -> Any:
            if users is None:
                return None
            return tags.div(
                tags.strong(f"{signed_in} {DOT} {role}. "),
                L.ROLE_NOTES[role],
                class_="cg-status neutral",
            )

        @render.ui
        def status() -> Any:
            n = len(changes())
            rev = saved.get().get("revision")
            if problem() is not None:
                return tags.div(
                    tags.strong("Not valid - cannot be saved. "), problem(), class_="cg-status bad"
                )
            if n:
                return tags.div(
                    tags.strong("Valid draft. "),
                    f"{n} unsaved change{'' if n == 1 else 's'} to revision {rev}.",
                    class_="cg-status pending",
                )
            return tags.div(
                tags.strong("Saved. "), f"Revision {rev}, no changes.", class_="cg-status ok"
            )

        @render.ui
        def header_status() -> Any:
            signed = (
                tags.span(
                    badge(f"{signed_in} {DOT} {role}", "neutral", "Signed in"), class_="cg-signed"
                )
                if users is not None
                else None
            )
            if role == "user":
                return signed
            r = test_results()
            tests_badge = None
            if isinstance(r, list) and r:
                passed = sum(t.passed for t in r)
                tests_badge = badge(
                    f"tests {passed}/{len(r)}", "allow" if passed == len(r) else "block"
                )
            if problem() is not None:
                state = badge("not valid", "block")
            elif changes():
                state = badge("unsaved changes", "redact")
            else:
                state = badge("saved", "allow")
            return TagList(
                signed,
                badge(draft.get().get("id") or "(no id)", "neutral"),
                badge(f"revision {saved.get().get('revision')}", "neutral"),
                tests_badge,
                state,
            )

        @render.ui
        def stats() -> Any:
            d = draft.get().get("destinations") or {}
            blocked = sum(1 for e in d.values() if (e or {}).get("blocked") is True)
            tiers = Counter((e or {}).get("tier") for e in d.values())
            n = len(changes())

            def stat(label: str, value: Any, note: str, kind: str = "") -> Tag:
                return tags.div(
                    tags.div(label, class_="label"),
                    tags.div(str(value), class_="value"),
                    tags.div(note, class_="note"),
                    class_=f"cg-stat {kind}",
                )

            note = f" {DOT} ".join(f"{tiers[t]} {t}" for t in ("local", "internal", "frontier"))
            if blocked:
                note += f" {DOT} {blocked} blocked"
            x = draft.get()
            return TagList(
                stat("Endpoints", len(d), note),
                stat(
                    "Rules",
                    len(x.get("rules") or []),
                    f"then {x.get('default_action') or '?'} by default",
                ),
                stat(
                    "Unsaved changes",
                    n,
                    "review them under Changes" if n else "draft matches the file",
                    "warn" if n else "",
                ),
                stat("Status", "Valid", "the proxy would load it", "ok")
                if problem() is None
                else stat("Status", "Invalid", "fix before saving", "bad"),
            )

        # --- endpoints ---------------------------------------------------------------
        @reactive.calc
        def endpoint_names() -> list[str]:
            return list((draft.get().get("destinations") or {}).keys())

        @reactive.effect
        def _endpoint_choices() -> None:
            names = endpoint_names()
            with reactive.isolate():
                keep = input.ep_pick() if "Endpoints" in L.TABS[role] else None
                rd = input.rule_destinations() if "Rules" in L.TABS[role] else None
                to = input.try_endpoint() if "Try it" in L.TABS[role] else None
            if "Endpoints" in L.TABS[role]:
                ui.update_select(
                    "ep_pick",
                    choices={"": "(new endpoint)", **{n: n for n in names}},
                    selected=keep if keep in names else "",
                )
            if "Rules" in L.TABS[role]:
                ui.update_selectize("rule_destinations", choices=names, selected=list(rd or ()))
            if "Try it" in L.TABS[role]:
                saved_names = list((saved.get().get("destinations") or {}).keys())
                choices = names if can_edit else saved_names
                ui.update_select(
                    "try_endpoint",
                    choices=choices,
                    selected=to if to in choices else (choices or [None])[0],
                )

        if "Endpoints" in L.TABS[role]:

            @render.ui
            def endpoints() -> Any:
                d = draft.get().get("destinations") or {}
                if not d:
                    return empty("No endpoints yet: every request would be refused.")
                pick = input.ep_pick() or ""
                rows = []
                for name, e in d.items():
                    e = e or {}
                    cls = " ".join(
                        c
                        for c in (
                            "selected" if name == pick else "",
                            "is-blocked" if e.get("blocked") else "",
                        )
                        if c
                    )
                    rows.append(
                        tags.tr(
                            tags.td(
                                tags.div(tags.strong(name), class_="name"),
                                tags.div(e["description"], class_="desc")
                                if e.get("description")
                                else None,
                            ),
                            tags.td(badge(e.get("tier") or "?", e.get("tier") or "neutral")),
                            tags.td(e.get("provider") or ""),
                            tags.td(e.get("url") or "", class_="mono"),
                            tags.td(
                                badge("blocked", "blocked")
                                if e.get("blocked")
                                else badge("open", "allow")
                            ),
                            class_=cls or None,
                            **{"data-pick": name, "data-target": "ep_pick"},
                        )
                    )
                return table(["Endpoint", "Tier", "Provider", "URL", "Requests"], rows)

            @render.ui
            def ep_form_title() -> Any:
                pick = input.ep_pick() or ""
                return tags.h6(f"Edit {pick}" if pick else "Add an endpoint")

            @reactive.effect
            @reactive.event(input.ep_pick)
            def _ep_pick() -> None:
                pick = input.ep_pick() or ""
                with reactive.isolate():
                    e = (
                        (draft.get().get("destinations") or {}).get(pick) or {}
                        if pick
                        else {"tier": "local"}
                    )
                ui.update_text("ep_name", value=pick)
                ui.update_select("ep_tier", selected=e.get("tier"))
                ui.update_text("ep_provider", value=e.get("provider") or "")
                ui.update_text("ep_url", value=e.get("url") or "")
                ui.update_text("ep_description", value=e.get("description") or "")
                ui.update_checkbox("ep_blocked", value=e.get("blocked") is True)

        if can_edit:

            @reactive.effect
            @reactive.event(input.ep_apply)
            def _ep_apply() -> None:
                name = (input.ep_name() or "").strip()
                if not name:
                    ui.notification_show("An endpoint needs a name.", type="error")
                    return
                old = input.ep_pick() or ""
                entry: dict[str, Any] = {"tier": input.ep_tier()}
                for f in ("provider", "url", "description"):
                    v = (input[f"ep_{f}"]() or "").strip()
                    if v:
                        entry[f] = v
                if input.ep_blocked():
                    entry["blocked"] = True

                def f(x: dict[str, Any]) -> dict[str, Any]:
                    d = dict(x.get("destinations") or {})
                    if old and old != name:
                        d = {(name if k == old else k): v for k, v in d.items()}
                        x["rules"] = [
                            L.rename_destination(r, old, name) for r in x.get("rules") or []
                        ]
                    d[name] = entry
                    x["destinations"] = d
                    return x

                edit(f)
                ui.update_select("ep_pick", selected=name)

            @reactive.effect
            @reactive.event(input.ep_delete)
            def _ep_delete() -> None:
                name = input.ep_pick() or ""
                if not name:
                    return
                used = [
                    r.get("id")
                    for r in draft.get().get("rules") or []
                    if name in ((r.get("when") or {}).get("destinations") or [])
                ]
                if used:
                    ui.notification_show(
                        f"Rule(s) {', '.join(used)} name this endpoint; change them first.",
                        type="error",
                    )
                    return

                def f(x: dict[str, Any]) -> dict[str, Any]:
                    x["destinations"] = {
                        k: v for k, v in (x.get("destinations") or {}).items() if k != name
                    }
                    return x

                edit(f)

        # --- rules -------------------------------------------------------------------
        @reactive.calc
        def rule_ids() -> list[str]:
            return [r.get("id") or "" for r in draft.get().get("rules") or []]

        if "Rules" in L.TABS[role]:
            ids_all = [d.id for d in builtin]
            ui.update_selectize("rule_types", choices=ids_all)
            ui.update_selectize("rule_all_of", choices=ids_all)
            ui.update_selectize(
                "rule_classes",
                choices=sorted(
                    {
                        "identity_strong",
                        "financial",
                        "sensitive_auth",
                        "health",
                        "contact",
                        "personal",
                        "quasi",
                    }
                    | {d.data_class for d in builtin}
                ),
            )

            @reactive.effect
            def _rule_choices() -> None:
                ids = rule_ids()
                with reactive.isolate():
                    keep = input.rule_pick()
                ui.update_select(
                    "rule_pick",
                    choices={"": "(new rule)", **{i: i for i in ids}},
                    selected=keep if keep in ids else "",
                )

            @render.ui
            def rules() -> Any:
                x = draft.get()
                pick = input.rule_pick() or ""
                labels = {
                    "destinations": "Endpoints",
                    "tiers": "Tiers",
                    "classes": "Classes",
                    "types": "Types",
                    "all_of": "All of",
                }
                cards = []
                for i, r in enumerate(x.get("rules") or [], start=1):
                    when = r.get("when") or {}
                    keys = [k for k in labels if k in when]
                    parts = (
                        [tags.span("Every identifier", class_="part")]
                        if not keys
                        else [
                            tags.span(
                                tags.span(labels[k], class_="key"),
                                *[tags.span(str(v), class_="cg-chip") for v in (when[k] or [])],
                                class_="part",
                            )
                            for k in keys
                        ]
                    )
                    cards.append(
                        tags.div(
                            tags.div(str(i), class_="order"),
                            tags.div(
                                tags.div(r.get("id"), class_="id"),
                                tags.div(r["description"], class_="desc")
                                if r.get("description")
                                else None,
                                tags.div(*parts, class_="when"),
                            ),
                            badge(r.get("action") or "?", r.get("action") or "neutral"),
                            class_="cg-rule selected" if r.get("id") == pick else "cg-rule",
                            **{"data-pick": r.get("id") or "", "data-target": "rule_pick"},
                        )
                    )
                default = x.get("default_action") or "?"
                cards.append(
                    tags.div(
                        tags.div("\u2013", class_="order"),
                        tags.div(
                            tags.div("Otherwise", class_="id"),
                            tags.div("When no rule matches (set in the sidebar)", class_="desc"),
                        ),
                        badge(default, default if default != "?" else "neutral"),
                        class_="cg-rule cg-rule-default",
                    )
                )
                return tags.div(*cards, class_="cg-rules")

            @render.ui
            def rule_form_title() -> Any:
                pick = input.rule_pick() or ""
                return tags.h6(f"Edit rule {pick}" if pick else "Add a rule (at the end)")

            @reactive.effect
            @reactive.event(input.rule_pick)
            def _rule_pick() -> None:
                pick = input.rule_pick() or ""
                with reactive.isolate():
                    ids = rule_ids()
                    r = (
                        (draft.get().get("rules") or [])[ids.index(pick)]
                        if pick in ids
                        else {"action": "redact"}
                    )
                ui.update_text("rule_id", value=pick)
                ui.update_select("rule_action", selected=r.get("action"))
                ui.update_text("rule_description", value=r.get("description") or "")
                for k in L.WHEN_KEYS:
                    ui.update_selectize(
                        f"rule_{k}", selected=list((r.get("when") or {}).get(k) or [])
                    )

        if can_edit:

            @reactive.effect
            @reactive.event(input.rule_apply)
            def _rule_apply() -> None:
                rid = (input.rule_id() or "").strip()
                if not rid:
                    ui.notification_show("A rule needs an id.", type="error")
                    return
                old = input.rule_pick() or ""
                when = {k: list(input[f"rule_{k}"]() or []) for k in L.WHEN_KEYS}
                when = {k: v for k, v in when.items() if v}
                rule: dict[str, Any] = {"id": rid}
                desc = (input.rule_description() or "").strip()
                if desc:
                    rule["description"] = desc
                if when:
                    rule["when"] = when
                rule["action"] = input.rule_action()

                def f(x: dict[str, Any]) -> dict[str, Any]:
                    rules = list(x.get("rules") or [])
                    ids = [r.get("id") for r in rules]
                    if old and old in ids:
                        rules[ids.index(old)] = rule
                    else:
                        rules.append(rule)
                    x["rules"] = rules
                    return x

                edit(f)
                ui.update_select("rule_pick", selected=rid)

            def move(by: int) -> None:
                ids = rule_ids()
                pick = input.rule_pick() or ""
                if pick not in ids:
                    return
                at = ids.index(pick)
                to = at + by
                if to < 0 or to >= len(ids):
                    return

                def f(x: dict[str, Any]) -> dict[str, Any]:
                    rules = list(x["rules"])
                    rules[at], rules[to] = rules[to], rules[at]
                    x["rules"] = rules
                    return x

                edit(f)

            @reactive.effect
            @reactive.event(input.rule_up)
            def _up() -> None:
                move(-1)

            @reactive.effect
            @reactive.event(input.rule_down)
            def _down() -> None:
                move(1)

            @reactive.effect
            @reactive.event(input.rule_delete)
            def _rule_delete() -> None:
                pick = input.rule_pick() or ""
                ids = rule_ids()
                if pick not in ids:
                    return
                at = ids.index(pick)
                edit(
                    lambda x: {
                        **x,
                        "rules": [r for i, r in enumerate(x.get("rules") or []) if i != at],
                    }
                )

        # --- try it ----------------------------------------------------------------------
        # Admins try the draft; everyone else the saved policy.
        @reactive.calc
        def try_policy() -> Policy | None:
            if can_edit:
                return compiled()
            p = L.policy_problem(saved.get(), base)
            return None if p else Policy.from_dict(saved.get(), base=base)

        @reactive.calc
        def try_problem() -> str | None:
            return problem() if can_edit else L.policy_problem(saved.get(), base)

        if "Try it" in L.TABS[role]:

            @reactive.calc
            def decision() -> Any:
                p = try_policy()
                req(p is not None, input.try_endpoint(), input.try_text())
                return p.decide(input.try_text(), input.try_endpoint())

            @render.ui
            def try_result() -> Any:
                if try_problem() is not None:
                    return tags.div(
                        tags.div(
                            tags.div("Fix the policy first", class_="big"),
                            tags.div(try_problem(), class_="small"),
                        ),
                        class_="cg-verdict neutral",
                    )
                d = decision()
                counts = Counter(m.action for m in d.matches)
                found = f" {DOT} ".join(f"{n} {a}" for a, n in sorted(counts.items()))
                if d.allowed:
                    found_text = (
                        f"{len(d.matches)} identifier(s) found: {found}."
                        if d.matches
                        else "No identifiers found."
                    )
                    return tags.div(
                        tags.div(
                            tags.div(f"✓ Sent to {d.destination}", class_="big"),
                            tags.div(f"{d.tier} tier. {found_text}", class_="small"),
                        ),
                        class_="cg-verdict ok",
                    )
                return tags.div(
                    tags.div(
                        tags.div(f"⛔ Blocked - nothing reaches {d.destination}", class_="big"),
                        tags.div(
                            f"{d.tier} tier. Blocked by rule {', '.join(d.blocked_by)}.",
                            class_="small",
                        ),
                    ),
                    class_="cg-verdict bad",
                )

            @render.ui
            def try_output() -> Any:
                d = decision()
                req(d.allowed)
                try:
                    text = try_policy().apply(input.try_text(), input.try_endpoint()).texts[0]  # type: ignore[union-attr]
                except Exception:
                    text = "(tokenising needs a vault; the proxy uses one)"
                return TagList(
                    tags.div("What the model receives", class_="cg-out-label"),
                    tags.div(text, class_="cg-out"),
                )

            @render.ui
            def try_matches() -> Any:
                d = decision()
                if not d.matches:
                    return None
                rows = [
                    tags.tr(
                        tags.td(
                            tags.strong(m.span.type), tags.div(m.span.data_class, class_="desc")
                        ),
                        tags.td(mask_value(m.span.value, m.span.data_class), class_="mono"),
                        tags.td(confidence_bar(m.span.confidence)),
                        tags.td(*why_list(m.span.reasons), class_="desc"),
                        tags.td(badge(m.action, m.action)),
                        tags.td("default action" if m.rule in ("", "default") else m.rule),
                    )
                    for m in d.matches
                ]
                return table(
                    ["Identifier", "Found (masked)", "Confidence", "Why", "Action", "Decided by"],
                    rows,
                )

            @render.ui
            def try_misses() -> Any:
                p = try_policy()
                req(p is not None, input.try_text())
                try:
                    _, misses = explain_pii(
                        input.try_text(), min_confidence=p.min_confidence, detectors=p.detectors
                    )
                except Exception:
                    misses = []
                head = tags.h6(
                    tip(
                        "Not reported",
                        "Text that looked like an identifier but was dropped, and why. A miss here "
                        "may be right (an order number that fails the Aadhaar checksum) or a sign "
                        "that the text needs a keyword or the minimum confidence is too high.",
                    ),
                    class_="cg-section",
                )
                body = (
                    empty("Nothing that looked like an identifier was dropped.")
                    if not misses
                    else table(
                        ["Looked like", "Text (masked)", "Why it was not reported"],
                        [
                            tags.tr(
                                tags.td(tags.strong(m.type)),
                                tags.td(mask_value(m.value, m.data_class), class_="mono"),
                                tags.td(m.why),
                            )
                            for m in misses
                        ],
                    )
                )
                hint = tags.div(
                    "Names are found after a cue (Mr., S/o, Name:) or in a column named for "
                    "names; a "
                    "name on its own is not. A custom detector can add cues: see the custom "
                    "detectors guide.",
                    class_="cg-hint",
                )
                return TagList(head, body, hint)

        # --- tests -----------------------------------------------------------------------
        tests_file = tests_path(path)

        def read_tests() -> list[dict[str, Any]]:
            if not tests_file.exists():
                return []
            data = yaml.safe_load(tests_file.read_text(encoding="utf-8")) or {}
            return list(data.get("tests") or [])

        try:
            first_tests = read_tests()
        except (OSError, ValueError, yaml.YAMLError):
            first_tests = []
        tests = reactive.value(first_tests)

        @reactive.calc
        def test_results() -> list[Any] | str | None:
            if not tests.get():
                return None
            p = try_policy()
            if p is None:
                return "The draft is not valid, so the tests cannot run."
            try:
                return run_policy_tests(
                    p, {"kind": "credgate-policy-tests", "version": 1, "tests": tests.get()}
                )
            except Exception as e:
                return str(e)

        @reactive.calc
        def failing() -> list[str]:
            r = test_results()
            return [t.id for t in r if not t.passed] if isinstance(r, list) else []

        @render.ui
        def tests_table() -> Any:
            r = test_results()
            if r is None:
                return empty(
                    "No tests yet. In Try it, check a decision is right, then save it as a test."
                )
            if isinstance(r, str):
                return tags.div(r, class_="cg-alert")
            pick = input.test_pick() if can_edit else None
            rows = []
            for t, res in zip(tests.get(), r, strict=False):
                rows.append(
                    tags.tr(
                        tags.td(
                            tags.strong(res.id),
                            tags.div(res.description, class_="desc") if res.description else None,
                        ),
                        tags.td(t.get("endpoint")),
                        tags.td(
                            badge("pass", "allow") if res.passed else badge("fail", "block"),
                            *[tags.div(p, class_="desc") for p in res.problems],
                        ),
                        class_="selected" if res.id == pick else None,
                        **{"data-pick": res.id, "data-target": "test_pick"},
                    )
                )
            return table(["Test", "Endpoint", "Result"], rows)

        if can_edit:

            @reactive.effect
            def _test_choices() -> None:
                ids = [t.get("id") for t in tests.get()]
                with reactive.isolate():
                    keep = input.test_pick()
                ui.update_select(
                    "test_pick", choices=ids, selected=keep if keep in ids else (ids or [None])[0]
                )

            def save_tests(x: list[dict[str, Any]]) -> bool:
                try:
                    p = compiled()
                    types = set(p.detector_ids) if p is not None else {d.id for d in builtin}
                    if x:
                        write_policy_tests(x, tests_file, types)
                    elif tests_file.exists():
                        tests_file.unlink()
                except Exception as e:
                    ui.notification_show(f"Tests not saved: {e}", type="error")
                    return False
                tests.set(x)
                return True

            @reactive.effect
            @reactive.event(input.test_add)
            def _test_add() -> None:
                tid = (input.test_id() or "").strip()
                if not tid:
                    ui.notification_show("Give the test an id.", type="error")
                    return
                if tid in [t.get("id") for t in tests.get()]:
                    ui.notification_show(f"There is already a test {tid}.", type="error")
                    return
                try:
                    d = decision()
                except Exception:
                    d = None
                if d is None:
                    ui.notification_show(
                        "Nothing to save: fix the policy and enter a request first.", type="error"
                    )
                    return
                t = test_from_decision(tid, input.try_text(), input.try_endpoint(), d)
                if save_tests([*tests.get(), t]):
                    ui.update_text("test_id", value="")
                    ui.notification_show(f"Test {tid} saved to {tests_file.name}.", type="message")

            @reactive.effect
            @reactive.event(input.test_delete)
            def _test_delete() -> None:
                keep = [t for t in tests.get() if t.get("id") != input.test_pick()]
                if len(keep) < len(tests.get()):
                    save_tests(keep)

            @render.ui
            def save_anyway_ui() -> Any:
                f = failing()
                if not f:
                    return None
                with reactive.isolate():
                    current = bool(input.save_anyway()) if "save_anyway" in input else False
                n = len(f)
                return tags.div(
                    f"{n} test{'' if n == 1 else 's'} fail{'s' if n == 1 else ''}: {', '.join(f)}.",
                    ui.input_checkbox(
                        "save_anyway",
                        "Save anyway (the change log records the failing tests; give the reason "
                        "above)",
                        value=current,
                    ),
                    class_="cg-alert",
                )

        # --- detector workbench ----------------------------------------------------------
        if "Detectors" in L.TABS[role]:

            @reactive.calc
            def det_files() -> list[str]:
                v = draft.get().get("detectors") or []
                return [str(f) for f in (v if isinstance(v, list) else [v])]

            @reactive.effect
            def _det_choices() -> None:
                files_ = det_files()
                with reactive.isolate():
                    keep = input.det_file()
                ui.update_select(
                    "det_file",
                    choices={**{f: f for f in files_}, "": "(new file)"},
                    selected=keep if keep in files_ else (files_[0] if files_ else ""),
                )

            @render.ui
            def det_new_name() -> Any:
                if input.det_file():
                    return None
                return ui.input_text(
                    "det_name",
                    tip("New file name", "Saved beside the policy, e.g. bank-detectors.yaml."),
                    placeholder="bank-detectors.yaml",
                    width="100%",
                )

            def det_load() -> None:
                f = input.det_file() or ""
                target = L.detector_path(path, f) if f else None
                text = (
                    target.read_text(encoding="utf-8")
                    if target and target.exists()
                    else L.DETECTORS_TEMPLATE
                )
                ui.update_text_area("det_yaml", value=text)

            @reactive.effect
            @reactive.event(input.det_file, ignore_none=False)
            def _det_file() -> None:
                det_load()

            @reactive.effect
            @reactive.event(input.det_revert)
            def _det_revert() -> None:
                det_load()

            @reactive.calc
            def det_check() -> dict[str, Any]:
                text = input.det_yaml() or ""
                req(text.strip())
                try:
                    data = yaml.safe_load(text)
                except yaml.YAMLError as e:
                    return {"error": f"Not valid YAML: {e}"}
                examples = []
                bare = data
                if isinstance(data, dict) and isinstance(data.get("detectors"), list):
                    examples = [
                        d.get("examples") if isinstance(d, dict) else None
                        for d in data["detectors"]
                    ]
                    bare = {
                        **data,
                        "detectors": [
                            {k: v for k, v in d.items() if k != "examples"}
                            if isinstance(d, dict)
                            else d
                            for d in data["detectors"]
                        ],
                    }
                try:
                    dets = [d for d, _ in _compile_file(bare)]
                except ValueError as e:
                    return {"error": str(e)}
                taken = [d.id for d in dets if d.id in builtin_ids]
                if taken:
                    return {
                        "error": f"`{taken[0]}` is the id of a built-in detector; choose another."
                    }
                results = []
                for det, ex in zip(dets, examples, strict=False):
                    if not isinstance(ex, dict):
                        continue
                    for want in ("match", "no_match"):
                        texts = [str(t) for t in (ex.get(want) or [])]
                        if not texts:
                            continue
                        hit = {s.doc for s in _detect_with([det], texts, [""] * len(texts))}
                        for i, t in enumerate(texts):
                            ok = (i in hit) if want == "match" else (i not in hit)
                            results.append({"id": det.id, "want": want, "text": t, "ok": ok})
                return {"dets": dets, "examples": results}

            @render.ui
            def det_status() -> Any:
                x = det_check()
                if "error" in x:
                    return tags.div(
                        tags.strong("Cannot be saved. "), x["error"], class_="cg-status bad"
                    )
                bad = sum(not e["ok"] for e in x["examples"])
                if bad:
                    return tags.div(
                        tags.strong(
                            f"{bad} example{'' if bad == 1 else 's'} "
                            f"fail{'s' if bad == 1 else ''}. "
                        ),
                        "Fix the pattern or the example before saving.",
                        class_="cg-status bad",
                    )
                ids = ", ".join(d.id for d in x["dets"])
                n = len(x["examples"])
                return tags.div(
                    tags.strong("Valid. "),
                    f"{ids}; {n} example{'' if n == 1 else 's'} hold.",
                    class_="cg-status ok",
                )

            @render.ui
            def det_matches() -> Any:
                x = det_check()
                req("error" not in x)
                lines = [ln for ln in (input.det_sample() or "").split("\n") if ln.strip()]
                if not lines:
                    return None
                misses: list[Any] = []
                found = _detect_with(x["dets"], lines, [""] * len(lines), 0.0, None, misses)
                sample = tags.div(
                    *[
                        tags.div(*highlight(line, [s for s in found if s.doc == i]), class_="line")
                        for i, line in enumerate(lines)
                    ],
                    class_="cg-sample",
                )
                found_table = (
                    table(
                        ["Detector", "Found", "Confidence", "Why"],
                        [
                            tags.tr(
                                tags.td(tags.strong(s.type)),
                                tags.td(s.value, class_="mono"),
                                tags.td(confidence_bar(s.confidence)),
                                tags.td(*why_list(s.reasons), class_="desc"),
                            )
                            for s in found
                        ],
                    )
                    if found
                    else empty("No matches on the sample.")
                )
                notes = (
                    tags.div(
                        *[
                            tags.div(f"Not reported: {m.type} '{m.value}' - {m.why}")
                            for m in misses
                        ],
                        class_="cg-hint",
                    )
                    if misses
                    else None
                )
                return TagList(
                    tags.h6("On the sample", class_="cg-section"), sample, found_table, notes
                )

            @render.ui
            def det_examples() -> Any:
                x = det_check()
                req("error" not in x, x["examples"])
                e = x["examples"]
                several = len({r["id"] for r in e}) > 1
                rows = [
                    tags.tr(
                        tags.td(
                            r["text"],
                            tags.div(r["id"], class_="desc") if several else None,
                            class_="mono",
                        ),
                        tags.td("match" if r["want"] == "match" else "not match"),
                        tags.td(
                            badge("holds", "allow")
                            if r["ok"]
                            else badge("missed" if r["want"] == "match" else "wrong match", "block")
                        ),
                    )
                    for r in e
                ]
                return TagList(
                    tags.h6("Examples", class_="cg-section"),
                    table(["Example", "Should", "Result"], rows),
                )

            @reactive.effect
            @reactive.event(input.gen_add)
            def _gen_add() -> None:
                det = L.detector_from_form(
                    input.gen_id(),
                    input.gen_class(),
                    input.gen_label(),
                    input.gen_pattern(),
                    input.gen_keywords(),
                    bool(input.gen_required()),
                    input.gen_match(),
                    input.gen_no_match(),
                )
                if isinstance(det, str):
                    ui.notification_show(det, type="error")
                    return
                text = input.det_yaml() or ""
                try:
                    data = yaml.safe_load(text) if text.strip() else {}
                except yaml.YAMLError:
                    data = None
                if not isinstance(data, dict):
                    ui.notification_show(
                        "The YAML below cannot be read; fix it before adding a detector.",
                        type="error",
                    )
                    return
                existing = [d.get("id") for d in data.get("detectors") or [] if isinstance(d, dict)]
                if det["id"] in existing:
                    ui.notification_show(
                        f"The file already has a detector {det['id']}.", type="error"
                    )
                    return
                rest = {k: v for k, v in data.items() if k not in ("kind", "version", "detectors")}
                out = {
                    "kind": "credgate-detectors",
                    "version": 1,
                    **rest,
                    "detectors": [*(data.get("detectors") or []), det],
                }
                ui.update_text_area("det_yaml", value=L.detectors_yaml(out))
                for f in ("gen_id", "gen_label", "gen_pattern", "gen_keywords"):
                    ui.update_text(f, value="")
                for f in ("gen_match", "gen_no_match"):
                    ui.update_text_area(f, value="")

        if can_edit:

            @reactive.effect
            @reactive.event(input.det_save)
            def _det_save() -> None:
                f = input.det_file() or ""
                new = not f
                if new:
                    f = (
                        L.new_detectors_file_name(input.det_name() if "det_name" in input else "")
                        or ""
                    )
                    if not f:
                        ui.notification_show(
                            "Give the new file a name ending in .yaml, without folders, e.g. "
                            "bank-detectors.yaml.",
                            type="error",
                        )
                        return
                    if L.detector_path(path, f).exists():
                        ui.notification_show(
                            f"{f} already exists; add it to the policy's detectors list to edit "
                            "it.",
                            type="error",
                        )
                        return
                text = input.det_yaml() or ""
                try:
                    data = yaml.safe_load(text)
                    ids = [d.id for d, _ in _compile_file(data)]
                    taken = [i for i in ids if i in builtin_ids]
                    if taken:
                        raise ValueError(f"`{taken[0]}` is the id of a built-in detector.")
                except yaml.YAMLError:
                    ui.notification_show("Not saved: not valid YAML.", type="error")
                    return
                except ValueError as e:
                    ui.notification_show(f"Not saved: {e}", type="error")
                    return
                target = L.detector_path(path, f)
                tmp = target.with_name(target.name + ".tmp")
                tmp.write_text(text.rstrip("\n") + "\n", encoding="utf-8")
                os.replace(tmp, target)
                if new:

                    def add(x: dict[str, Any]) -> dict[str, Any]:
                        v = x.get("detectors") or []
                        x["detectors"] = [*(v if isinstance(v, list) else [v]), f]
                        return x

                    edit(add)
                    ui.update_select("det_file", selected=f)
                det_saved_at.set(det_saved_at.get() + 1)
                ui.notification_show(
                    f"Saved {target.name}. Save a new policy revision too, so the audit log shows "
                    "the change.",
                    type="message",
                    duration=8,
                )

        # --- proxy keys --------------------------------------------------------------------
        @reactive.calc
        def people() -> Any:
            keys_changed.get()
            if users is None:
                return None
            try:
                return read_users(users)
            except (OSError, ValueError):
                return None

        @reactive.calc
        def durations() -> dict[str, int]:
            p = people()
            most = p.settings.get("key_max_days", 90) if p is not None else 90
            return {k: v for k, v in L.KEY_DURATIONS.items() if v <= most}

        def key_row(name: str) -> dict[str, Any] | None:
            if keys is None or not Path(keys).exists():
                return None
            return next((u for u in _keys.list_users(keys) if u["name"] == name), None)

        def show_new_key(title: str, key: str, for_whom: str) -> None:
            ui.modal_show(
                ui.modal(
                    tags.p(
                        f"The key for {for_whom}. Copy it now: it is not shown again, and "
                        "credgate keeps "
                        "only a hash of it."
                    ),
                    tags.div(
                        tags.code(key, class_="cg-key", id="cg-new-key"),
                        tags.button(
                            "Copy",
                            type="button",
                            class_="btn btn-primary btn-sm",
                            onclick="cgCopyKey(this)",
                        ),
                        class_="cg-key-row",
                    ),
                    title=title,
                    easy_close=False,
                    footer=ui.modal_button("Done"),
                )
            )

        def days_ok(value: Any) -> int | None:
            try:
                days = int(value)
            except (TypeError, ValueError):
                days = None
            if days is None or days not in durations().values():
                ui.notification_show("Choose how long the key is valid.", type="error")
                return None
            return days

        def make_key(name: str, days: int, by: str) -> str:
            assert keys is not None
            exists = Path(keys).exists() and name in _keys.read_keys(keys)
            key = _keys.rotate_key(keys, name, days) if exists else _keys.add_user(keys, name, days)
            row = key_row(name)
            _keys.log_access(
                keys, by, "rotate" if exists else "create", name, row and row.get("expires")
            )
            keys_changed.set(keys_changed.get() + 1)
            return key

        @render.ui
        def my_key() -> Any:
            keys_changed.get()
            if keys is None:
                return empty("No keys file is set up for this app; ask your InfoSec team.")
            try:
                row = key_row(me)
            except (OSError, ValueError):
                row = None
            d = durations()
            choices = {str(v): k for k, v in d.items()}
            return TagList(
                tags.div(
                    tags.strong(f"{me}: {row['status']}. "),
                    f"Made {(row['created'] or '-')[:10]}, valid until "
                    f"{(row['expires'] or 'never')[:10]}.",
                    class_="cg-status neutral",
                )
                if row
                else empty(f"{me} has no proxy key yet."),
                tags.div(
                    ui.input_select("my_days", "Valid for", choices, selected=str(max(d.values()))),
                    ui.input_action_button(
                        "my_new_key",
                        "New key (the old one stops working)" if row else "Make my key",
                        class_="btn-primary btn-sm",
                    ),
                    ui.input_action_button(
                        "my_remove_key", "Delete my key", class_="btn-outline-danger btn-sm"
                    )
                    if row
                    else None,
                    class_="cg-actions cg-field-row",
                ),
            )

        @reactive.effect
        @reactive.event(input.my_new_key)
        def _my_new_key() -> None:
            days = days_ok(input.my_days())
            if days is None or keys is None:
                return
            try:
                key = make_key(me, days, me)
            except (OSError, ValueError) as e:
                ui.notification_show(str(e), type="error")
                return
            show_new_key("Your new key", key, me)

        @reactive.effect
        @reactive.event(input.my_remove_key)
        def _my_remove_key() -> None:
            if keys is None:
                return
            try:
                _keys.remove_user(keys, me)
                _keys.log_access(keys, me, "remove", me)
            except (OSError, ValueError) as e:
                ui.notification_show(str(e), type="error")
                return
            keys_changed.set(keys_changed.get() + 1)
            ui.notification_show(
                "Your key is deleted; it stops working at the proxy's next reload.", type="message"
            )

        if "Users" in L.TABS[role]:

            @render.ui
            def users_table() -> Any:
                keys_changed.get()
                p = people()
                k = (
                    {u["name"]: u for u in _keys.list_users(keys)}
                    if keys and Path(keys).exists()
                    else {}
                )
                rows_ = (
                    [(n, u.role, u.active) for n, u in p.users.items()]
                    if p is not None
                    else [(n, None, True) for n in k]
                )
                if not rows_:
                    return empty("No users yet.")
                return table(
                    ["User", "Role", "Access", "Proxy key", "Valid until"],
                    [
                        tags.tr(
                            tags.td(tags.strong(n)),
                            tags.td(r or "-"),
                            tags.td(badge("active", "allow") if a else badge("inactive", "block")),
                            tags.td(k[n]["status"] if n in k else "none"),
                            tags.td(
                                (k[n]["expires"] or "-")[:10] if n in k else "-", class_="mono"
                            ),
                        )
                        for n, r, a in rows_
                    ],
                )

            @render.ui
            def access_log() -> Any:
                keys_changed.get()
                if keys is None:
                    return None
                entries, intact = _keys.read_access(keys)
                alert = (
                    None
                    if intact
                    else tags.div(
                        "The access log was altered: entries were edited or removed after they "
                        "were written.",
                        class_="cg-alert",
                    )
                )
                if not entries:
                    return TagList(alert, empty("No key changes yet."))
                items = [
                    tags.li(
                        f"{a.time.removesuffix('Z').replace('T', ' ')} {DOT} {a.by}: "
                        f"{a.action} key for {a.user}"
                        + (f", valid until {a.expires[:10]}" if a.expires else "")
                    )
                    for a in reversed(entries)
                ]
                return TagList(alert, tags.ul(*items, class_="cg-diff"))

        if can_edit:

            @reactive.effect
            def _user_choices() -> None:
                p = people()
                keys_changed.get()
                names = (
                    list(p.users)
                    if p is not None
                    else [u["name"] for u in _keys.list_users(keys)]
                    if keys and Path(keys).exists()
                    else []
                )
                d = durations()
                with reactive.isolate():
                    keep = input.user_pick()
                ui.update_select(
                    "user_pick", choices=names, selected=keep if keep in names else None
                )
                ui.update_select(
                    "user_days",
                    choices={str(v): k for k, v in d.items()},
                    selected=str(max(d.values())),
                )

            @reactive.effect
            @reactive.event(input.user_new_key)
            def _user_new_key() -> None:
                name = input.user_pick() or ""
                if keys is None or not name:
                    return
                days = days_ok(input.user_days())
                if days is None:
                    return
                try:
                    key = make_key(name, days, me)
                except (OSError, ValueError) as e:
                    ui.notification_show(str(e), type="error")
                    return
                show_new_key(f"New key for {name}", key, name)

            @reactive.effect
            @reactive.event(input.user_remove_key)
            def _user_remove_key() -> None:
                name = input.user_pick() or ""
                if keys is None or not name:
                    return
                try:
                    _keys.remove_user(keys, name)
                    _keys.log_access(keys, me, "remove", name)
                except (OSError, ValueError) as e:
                    ui.notification_show(str(e), type="error")
                    return
                keys_changed.set(keys_changed.get() + 1)
                ui.notification_show(f"{name}'s key is removed.", type="message")

        @render.ui
        def my_activity() -> Any:
            if audit is None:
                return empty("No audit log is set up for this app.")
            p = people()
            days = p.settings.get("activity_days", 7) if p is not None else 7
            most = p.settings.get("activity_max", 100) if p is not None else 100
            try:
                a = own_activity(audit, me, days, most)
            except (OSError, ValueError, KeyError):
                return tags.div("The audit log could not be read.", class_="cg-alert")
            if not a:
                return empty(f"No requests from {me} in the last {days} days.")
            return TagList(
                tags.p(
                    f"The last {days} days, at most {most} requests, newest first.",
                    class_="cg-hint",
                ),
                table(
                    ["When", "Endpoint", "Result", "Identifiers"],
                    [
                        tags.tr(
                            tags.td(r.time[:19].replace("T", " "), class_="mono"),
                            tags.td(r.endpoint),
                            tags.td(
                                badge("allowed", "allow")
                                if r.allowed
                                else badge("blocked", "block"),
                                None if r.allowed else tags.div(r.blocked_by, class_="desc"),
                            ),
                            tags.td(r.found, class_="desc"),
                        )
                        for r in a
                    ],
                ),
            )

        # --- changes and saving --------------------------------------------------------------
        if role != "user":

            @render.ui
            def pending() -> Any:
                ch = changes()
                if not ch:
                    return empty("No unsaved changes: the draft matches the saved file.")

                def kind(c: str) -> str:
                    return "add" if " added" in c else "del" if c.endswith(" removed") else "mod"

                return tags.ul(*[tags.li(c, class_=kind(c)) for c in ch], class_="cg-diff")

        @reactive.calc
        def history_calc() -> Any:
            saved_at.get()
            return policy_changes(path)

        @render.ui
        def history() -> Any:
            h = history_calc()
            if role == "user":
                # Users see when the policy changed, not who changed it or why.
                if not h.entries:
                    return empty("The policy has not been changed yet.")
                return tags.ul(
                    *[
                        tags.li(
                            f"Revision {e.revision} {DOT} {e.time[:10]} {DOT} {len(e.changes)} "
                            f"change{'' if len(e.changes) == 1 else 's'}"
                        )
                        for e in reversed(h.entries)
                    ],
                    class_="cg-diff",
                )
            alert = (
                None
                if h.intact
                else tags.div(
                    "The change log was altered: entries were edited or removed after they were "
                    "written.",
                    class_="cg-alert",
                )
            )
            if not h.entries:
                return TagList(alert, empty("No saves yet. The first save starts the change log."))
            return TagList(
                alert,
                tags.div(
                    *[
                        tags.div(
                            tags.div(
                                tags.span(f"Revision {e.revision}", class_="rev"),
                                tags.span(
                                    f" {DOT} {e.user} {DOT} {e.time.replace('T', ' ')}",
                                    class_="meta",
                                ),
                                class_="head",
                            ),
                            tags.div(e.note, class_="note") if e.note else None,
                            tags.ul(*[tags.li(c) for c in e.changes]),
                            class_="cg-entry",
                        )
                        for e in reversed(h.entries)
                    ],
                    class_="cg-timeline",
                ),
            )

        if can_edit:

            @reactive.calc
            def can_save() -> bool:
                anyway = bool(input.save_anyway()) if "save_anyway" in input else False
                return problem() is None and bool(changes()) and (not failing() or anyway)

            @reactive.effect
            def _save_button() -> None:
                ui.update_action_button("save", disabled=not can_save())

            @reactive.effect
            @reactive.event(input.save)
            def _save() -> None:
                if not can_save():
                    return
                name = (input.user() or "").strip()
                if not name:
                    ui.notification_show("Enter your name for the change log.", type="error")
                    return
                note = (input.note() or "").strip()
                if failing():
                    if not note:
                        ui.notification_show(
                            'Tests fail: say why you are saving anyway under "Why this change".',
                            type="error",
                        )
                        return
                    note = f"{note} [saved with failing tests: {', '.join(failing())}]"
                x = {**draft.get(), "revision": saved.get().get("revision")}
                try:
                    written = write_policy(x, path, user=name, note=note)
                except Exception as e:
                    ui.notification_show(f"Not saved: {e}", type="error")
                    return
                saved.set(written)
                draft.set(copy.deepcopy(written))
                saved_at.set(saved_at.get() + 1)
                ui.update_text("note", value="")
                if "save_anyway" in input:
                    ui.update_checkbox("save_anyway", value=False)
                ui.notification_show(f"Saved revision {written['revision']}.", type="message")

            @reactive.effect
            @reactive.event(input.reload)
            def _reload() -> None:
                x = L.read_draft(path)
                saved.set(x)
                draft.set(copy.deepcopy(x))
                load_fields(x)

    return App(page, server)
