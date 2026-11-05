"""The policy editor (Shiny for Python): the same app as the R package's
``policy_editor()``, on the same files. Needs ``pip install 'credgate[editor]'``."""

from __future__ import annotations

import os
from typing import Any

__all__ = ["policy_editor"]


def policy_editor(
    path: str | os.PathLike[str],
    user: str | None = None,
    users: str | os.PathLike[str] | None = None,
    keys: str | os.PathLike[str] | None = None,
    audit: str | os.PathLike[str] | None = None,
    trust_header: str | None = None,
) -> Any:
    """A Shiny app to edit a credgate policy without writing YAML.

    The model endpoints and their tiers, the rules in order (first match
    wins), the default action; every edit is checked with the same strict
    rules the proxy uses, and an invalid policy cannot be saved. **Try it**
    shows what the policy does with a sample text; **Tests** runs the
    policy's tests; **Detectors** edits and tries custom detectors;
    **Changes** shows what changed and the hash-chained change log. With a
    users file, each person sees what their role allows and manages their
    own proxy key. The R editor (``credgate::policy_editor()``) is the same
    app, and both work on the same files.

    Run it with ``credgate editor --policy bank.yaml`` or, for a server,
    ``uvicorn``/``shiny run`` on the returned app.

    Args:
        path: The policy file (YAML). A new file starts from the example
            bank policy.
        user: Who is editing, for the change log; with ``users``, also who
            is signed in. On a server leave it out and use ``trust_header``.
        users: A users file (``credgate users ...``): who may use the app and
            in which role. Admins change everything; auditors see but change
            nothing; users try the saved policy, see test results and try
            detectors. Anyone not in the file, or inactive, has no access.
            Without a users file everyone is an admin.
        keys: The proxy's keys file: everyone manages their own key under
            **My key**, admins everyone's under **Users**; each change goes
            to the access log beside it.
        audit: The proxy's audit log, for **My activity** (each person's own
            requests; never content).
        trust_header: With single sign-on in front of the app, the request
            header that carries the signed-in user (e.g.
            ``"X-Auth-Request-User"``). Only when the app is reachable through
            that sign-in proxy alone (listening on 127.0.0.1).

    Returns:
        A ``shiny.App``.
    """
    try:
        from ._app import make_app
    except ImportError as e:  # pragma: no cover - depends on the extra
        raise ImportError(
            "The policy editor needs Shiny for Python: pip install 'credgate[editor]'."
        ) from e
    return make_app(path, user=user, users=users, keys=keys, audit=audit, trust_header=trust_header)
