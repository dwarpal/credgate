"""Policies: what happens to each identifier in a request to a destination
(the spec's "Policies" rules)."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import detectors as _reg
from ._frames import texts as _texts
from .detect import Span, _detect_with
from .redact import placeholder
from .tokenise import Vault

TIERS = ("local", "internal", "frontier")
ACTIONS = ("allow", "redact", "tokenise", "block")
CLASSES = (
    "identity_strong",
    "financial",
    "sensitive_auth",
    "health",
    "contact",
    "personal",
    "quasi",
)
_TOP_FIELDS = {
    "policy",
    "version",
    "id",
    "revision",
    "description",
    "detectors",
    "destinations",
    "min_confidence",
    "rules",
    "default_action",
}
_RULE_FIELDS = {"id", "description", "when", "action"}
_WHEN_FIELDS = {"destinations", "tiers", "types", "classes", "all_of"}
_DESTINATION_FIELDS = {"tier", "provider", "url", "description", "blocked"}


class PolicyError(ValueError):
    """A policy that cannot be read correctly, or a request it cannot decide
    (an unknown destination). Never applied partly."""


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    destinations: frozenset[str] | None = None
    tiers: frozenset[str] | None = None
    types: frozenset[str] | None = None
    classes: frozenset[str] | None = None
    all_of: frozenset[str] | None = None
    description: str | None = None

    def matches(self, span: Span, destination: str, tier: str, found: set[str]) -> bool:
        return (
            (self.destinations is None or destination in self.destinations)
            and (self.tiers is None or tier in self.tiers)
            and (self.types is None or span.type in self.types)
            and (self.classes is None or span.data_class in self.classes)
            and (self.all_of is None or self.all_of <= found)
        )


@dataclass(frozen=True)
class PolicyMatch:
    """One identifier in a request, the action for it and the rule that
    decided (``"default"`` when no rule matched)."""

    span: Span
    action: str
    rule: str


@dataclass(frozen=True)
class Decision:
    """The outcome of a policy for one request.

    ``texts`` holds the rewritten texts when the request is allowed and the
    policy was applied (``None`` for :meth:`Policy.decide`, and whenever the
    request is blocked: nothing may be sent).
    """

    policy_id: str
    policy_revision: int
    destination: str
    tier: str
    allowed: bool
    blocked_by: tuple[str, ...]
    matches: tuple[PolicyMatch, ...]
    texts: list[str] | None = None
    provider: str | None = None
    url: str | None = None

    def __str__(self) -> str:
        head = f"Policy {self.policy_id} (revision {self.policy_revision}), "
        head += f"destination {self.destination} ({self.tier}): "
        if not self.allowed:
            head += f"BLOCKED by {', '.join(self.blocked_by)}"
        else:
            head += "allowed"
        lines = [head]
        for m in self.matches:
            lines.append(f"  {placeholder(m.span.type):<16} {m.action:<9} {m.rule}")
        return "\n".join(lines)


@dataclass(frozen=True)
class Destination:
    """An endpoint requests may go to, as set up in the policy."""

    name: str
    tier: str
    provider: str | None = None
    url: str | None = None
    description: str | None = None
    blocked: bool = False


class Policy:
    """A loaded, validated policy. Use :meth:`load` for a YAML file or
    :meth:`from_dict` for a mapping."""

    def __init__(
        self,
        id: str,
        revision: int,
        destinations: Mapping[str, Destination],
        rules: Sequence[Rule],
        default_action: str,
        min_confidence: float = 0.0,
        description: str | None = None,
        detectors: Mapping[str, _reg.Detector] | None = None,
    ) -> None:
        self.id = id
        self.revision = revision
        self.destinations = dict(destinations)
        self.rules = tuple(rules)
        self.default_action = default_action
        self.min_confidence = min_confidence
        self.description = description
        # The detectors this policy decides with: those registered when it
        # was loaded plus its own files. Fixed, so a policy loaded later (a
        # proxy reloading) never changes what this one detects. None: the
        # detectors registered at the time of each decision.
        self._detectors = None if detectors is None else dict(detectors)
        # The files it was loaded from, with a digest of each (see sources).
        self._sources: tuple[tuple[str, str], ...] = ()

    @property
    def detector_ids(self) -> list[str]:
        """The ids of the detectors this policy decides with."""
        dets = self._detectors if self._detectors is not None else _reg._detectors()
        return list(dets)

    @property
    def sources(self) -> tuple[tuple[str, str], ...]:
        """The files the policy was loaded from - the policy file and its
        custom detector files - each with the SHA-256 of its contents, so a
        change to any of them can be noticed. Empty for :meth:`from_dict`."""
        return self._sources

    def __repr__(self) -> str:
        return (
            f"<credgate.Policy {self.id} revision {self.revision}: "
            f"{len(self.rules)} rules, {len(self.destinations)} destinations>"
        )

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Policy:
        """Load and validate a policy file (YAML)."""
        raw = Path(path).read_bytes()
        data = yaml.safe_load(raw.decode("utf-8"))
        policy = _parse(data, Path(path).parent)
        policy._sources = ((str(path), hashlib.sha256(raw).hexdigest()), *policy._sources)
        return policy

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Policy:
        """Validate a policy given as a mapping (as read from YAML). Custom
        detector files it names are found relative to the working directory."""
        return _parse(data, Path.cwd())

    def decide(self, text: str | Sequence[str], destination: str) -> Decision:
        """Decide what happens to each identifier in a request to ``destination``,
        without changing the texts."""
        dest = self._destination(destination)
        tier = dest.tier
        docs = _texts(text)[0]
        dets = self._detectors if self._detectors is not None else _reg._detectors()
        spans = _detect_with(list(dets.values()), docs, [""] * len(docs), self.min_confidence)
        found = {s.type for s in spans}
        matches = []
        for span in spans:
            rule = next((r for r in self.rules if r.matches(span, destination, tier, found)), None)
            if rule is None:
                matches.append(PolicyMatch(span, self.default_action, "default"))
            else:
                matches.append(PolicyMatch(span, rule.action, rule.id))
        blocked = (("destination-blocked",) if dest.blocked else ()) + tuple(
            dict.fromkeys(m.rule for m in matches if m.action == "block")
        )
        return Decision(
            policy_id=self.id,
            policy_revision=self.revision,
            destination=destination,
            tier=tier,
            allowed=not blocked,
            blocked_by=blocked,
            matches=tuple(matches),
            provider=dest.provider,
            url=dest.url,
        )

    def apply(
        self,
        text: str | Sequence[str],
        destination: str,
        vault: Vault | None = None,
        audit: Any = None,
    ) -> Decision:
        """Decide, then rewrite the texts if the request is allowed: matches to
        redact become placeholders, matches to tokenise become tokens from
        ``vault``. A blocked request gets no texts. With ``audit`` (an
        :class:`~credgate.AuditLog`), the decision is recorded, blocked or not."""
        decision = self.decide(text, destination)
        if audit is not None:
            audit.record(decision)
        if not decision.allowed:
            return decision
        if vault is None and any(m.action == "tokenise" for m in decision.matches):
            raise PolicyError("This policy tokenises; pass a vault to apply it.")
        out = list(_texts(text)[0])
        replacements = []
        for m in decision.matches:  # document, then position order: tokens numbered in order
            if m.action == "redact":
                replacements.append((m.span, placeholder(m.span.type)))
            elif m.action == "tokenise":
                replacements.append((m.span, vault._token_for(m.span)))
        for span, new in sorted(replacements, key=lambda r: (r[0].doc, -r[0].start)):
            out[span.doc] = out[span.doc][: span.start] + new + out[span.doc][span.end :]
        return Decision(**{**decision.__dict__, "texts": out})

    def _destination(self, destination: str) -> Destination:
        found = self.destinations.get(destination)
        if found is None:
            known = ", ".join(sorted(self.destinations)) or "none"
            raise PolicyError(
                f"Unknown destination '{destination}' for policy {self.id}; known: {known}."
            )
        return found


def _load_custom_detectors(
    files: Any, base: Path
) -> tuple[list[_reg.Detector], list[tuple[str, str]]]:
    """The custom detector files named by the policy, compiled for the
    policy alone (not registered), so rules can name their types; and each
    file with the digest of its contents."""
    if files is None:
        return [], []
    if not isinstance(files, list) or not all(isinstance(f, str) and f for f in files):
        raise PolicyError("`detectors` must be a list of custom detector files.")
    from .custom import _compile_source

    dets: list[_reg.Detector] = []
    sources = []
    for f in files:
        path = Path(f) if Path(f).is_absolute() else base / f
        try:
            raw = path.read_bytes()
            compiled = _compile_source(path)
        except (OSError, ValueError) as e:
            raise PolicyError(f"Custom detectors {f}: {e}") from None
        for det, _ in compiled:
            if any(d.id == det.id for d in dets):
                raise PolicyError(f"Custom detectors {f}: `{det.id}` is also in another file.")
            dets.append(det)
        sources.append((str(path), hashlib.sha256(raw).hexdigest()))
    return dets, sources


def _parse(data: Any, base: Path) -> Policy:
    if not isinstance(data, Mapping) or data.get("policy") != "credgate-policy":
        raise PolicyError("Not a credgate policy: it must start with `policy: credgate-policy`.")
    _check_fields(data, _TOP_FIELDS, "policy")
    if data.get("version") != 1:
        raise PolicyError(f"Unsupported policy format version {data.get('version')!r}.")
    own, sources = _load_custom_detectors(data.get("detectors"), base)
    registry = dict(_reg._detectors())
    registry.update({d.id: d for d in own})
    pid = data.get("id")
    if not isinstance(pid, str) or not pid:
        raise PolicyError("The policy needs an `id`.")
    revision = data.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise PolicyError("`revision` must be a positive whole number.")
    min_conf = data.get("min_confidence", 0)
    if (
        isinstance(min_conf, bool)
        or not isinstance(min_conf, int | float)
        or not 0 <= min_conf <= 1
    ):
        raise PolicyError("`min_confidence` must be a number from 0 to 1.")

    dests = data.get("destinations")
    if not isinstance(dests, Mapping) or not dests:
        raise PolicyError("The policy needs at least one destination.")
    destinations = {}
    for name, spec in dests.items():
        if not isinstance(spec, Mapping):
            raise PolicyError(f"Destination '{name}' must be a mapping with a `tier`.")
        _check_fields(spec, _DESTINATION_FIELDS, f"destination '{name}'")
        if spec.get("tier") not in TIERS:
            raise PolicyError(
                f"Destination '{name}': unknown tier {spec.get('tier')!r}; "
                f"tiers are {', '.join(TIERS)}."
            )
        if not isinstance(spec.get("blocked", False), bool):
            raise PolicyError(f"Destination '{name}': `blocked` must be true or false.")
        for key in ("provider", "url", "description"):
            if key in spec and not isinstance(spec[key], str):
                raise PolicyError(f"Destination '{name}': `{key}` must be text.")
        destinations[str(name)] = Destination(
            str(name),
            spec["tier"],
            spec.get("provider"),
            spec.get("url"),
            spec.get("description"),
            spec.get("blocked", False),
        )

    types = set(registry)
    classes = set(CLASSES) | {d.data_class for d in registry.values()}
    rules: list[Rule] = []
    seen: set[str] = set()
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise PolicyError("`rules` must be a list (it may be empty).")
    for raw in raw_rules:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("id"), str):
            raise PolicyError("Every rule needs an `id`.")
        rid = raw["id"]
        if rid in seen:
            raise PolicyError(f"Duplicate rule id '{rid}'.")
        seen.add(rid)
        _check_fields(raw, _RULE_FIELDS, f"rule '{rid}'")
        if raw.get("action") not in ACTIONS:
            raise PolicyError(
                f"Rule '{rid}': unknown action {raw.get('action')!r}; "
                f"actions are {', '.join(ACTIONS)}."
            )
        when = raw.get("when") or {}
        if not isinstance(when, Mapping):
            raise PolicyError(f"Rule '{rid}': `when` must be a mapping.")
        _check_fields(when, _WHEN_FIELDS, f"rule '{rid}' `when`")
        cond = {}
        for key, allowed, what in (
            ("destinations", set(destinations), "destination"),
            ("tiers", set(TIERS), "tier"),
            ("types", types, "type"),
            ("classes", classes, "class"),
            ("all_of", types, "type"),
        ):
            if key in when:
                values = when[key]
                if not isinstance(values, list) or not values:
                    raise PolicyError(f"Rule '{rid}': `{key}` must be a non-empty list.")
                unknown = [v for v in values if v not in allowed]
                if unknown:
                    raise PolicyError(
                        f"Rule '{rid}': unknown {what} {', '.join(map(str, unknown))}."
                    )
                cond[key] = frozenset(values)
        rules.append(Rule(rid, raw["action"], description=raw.get("description"), **cond))

    default = data.get("default_action")
    if default not in ACTIONS:
        raise PolicyError(f"`default_action` must be one of {', '.join(ACTIONS)}, not {default!r}.")
    policy = Policy(
        pid,
        revision,
        destinations,
        rules,
        default,
        min_confidence=float(min_conf),
        description=data.get("description"),
        detectors=registry,
    )
    policy._sources = tuple(sources)
    return policy


def _check_fields(data: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(map(str, data)) - allowed)
    if unknown:
        raise PolicyError(f"Unknown field(s) in {where}: {', '.join(unknown)}.")
