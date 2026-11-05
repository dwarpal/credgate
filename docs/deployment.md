# Deployment

How to run credgate for a team: the **proxy** that people's tools talk to,
and the **app** (the policy editor, in R or Python) where InfoSec manages the policy and
everyone manages their own key - on one server or several. Everything here
is open source with permissive licences (credgate is Apache-2.0; nginx is
BSD, OAuth2 Proxy MIT, Keycloak and Caddy Apache-2.0).

```
 people's tools ──(their own cgk_ key)──► credgate proxy ──(endpoint keys)──► Anthropic, OpenAI,
 (Claude Code, SDKs, notebooks)           (one or more)                         vLLM, Ollama ...
                                                │ reads (and reloads)
                     policy.yaml (+ tests, detectors) · keys.json · users.yaml
                                                │ writes
 people's browsers ──► web server with single sign-on ──► credgate app (127.0.0.1 only)
                       (nginx/Apache/Caddy + OAuth2 Proxy or Keycloak)
```

## The files

Keep them together, owned by a service account, readable by the proxy and
writable by the app:

| File | What | Changed by |
|---|---|---|
| `policy.yaml`, `policy.tests.yaml`, detector files | the policy and its tests | admins, in the app |
| `policy.changes.jsonl` | change log of the policy (hash-chained) | the app, on each save |
| `keys.json` | each person's key hash and expiry | everyone (own key) and admins, in the app; `credgate proxy add-user ...` |
| `keys.access.jsonl` | who made, renewed or removed keys (hash-chained) | the app |
| `users.yaml` | who may use the app, their role, whether active | the super admin, on the server (`credgate users ...`), or an export from AD/LDAP |
| `audit.jsonl` (monthly files) | every request through the proxy, without content | the proxy |

```
/srv/credgate/
  policy.yaml  policy.tests.yaml  detectors/  policy.changes.jsonl
  keys.json  keys.access.jsonl  users.yaml
  audit/      # one audit log per proxy instance
```

## The proxy

```sh
credgate proxy serve \
  --policy /srv/credgate/policy.yaml --keys /srv/credgate/keys.json \
  --users /srv/credgate/users.yaml --require-tests \
  --audit /srv/credgate/audit/audit-$(hostname).jsonl \
  --host 0.0.0.0 --port 8790 --certfile proxy.pem --keyfile proxy.key \
  --server uvicorn --workers 4 --watch 10
```

- The endpoints' own keys go in the service's environment
  (`CREDGATE_UPSTREAM_KEY_CLAUDE=...`), never in files people can read.
- `--watch 10` picks up a new policy revision, a changed keys file or users
  file within 10 seconds; a revision that does not load or fails its tests
  is refused and the running one stays ([details](proxy.md#rolling-out-a-new-revision)).
- Run it as a systemd service, with `ExecReload=/bin/kill -HUP $MAINPID` so
  `systemctl reload` reloads at once.
- `/healthz` (no key needed) shows the running revision, for monitoring and
  load balancers.

## The app, behind single sign-on

The app does not handle passwords. A web server in front signs people in
with the bank's single sign-on and passes the signed-in name to the app in a
header; the app looks the name up in `users.yaml` for the role.

**1. Run the app on 127.0.0.1 only**, so it is reachable through the
sign-in proxy alone (otherwise anyone could send the header themselves):

```r
# app.R, run with: Rscript -e 'shiny::runApp("app.R", host = "127.0.0.1", port = 3838)'
credgate::policy_editor(
  "/srv/credgate/policy.yaml",
  users = "/srv/credgate/users.yaml",
  keys = "/srv/credgate/keys.json",
  audit = "/srv/credgate/audit/audit-proxy1.jsonl",
  trust_header = "X-Auth-Request-User"
)
```

Run it with `shiny::runApp()` as above (as a systemd service) rather than
Shiny Server: the open-source Shiny Server is AGPL-licensed.

Or the same app in Python (`pip install 'credgate[editor]'`; Shiny for
Python is MIT-licensed and runs on uvicorn):

```sh
credgate editor --policy /srv/credgate/policy.yaml --users /srv/credgate/users.yaml \
  --keys /srv/credgate/keys.json --audit /srv/credgate/audit/audit-proxy1.jsonl \
  --trust-header X-Auth-Request-User --host 127.0.0.1 --port 3838 --no-browser
```

It refuses `--trust-header` unless it listens on `127.0.0.1`.

**2. Put the sign-in proxy in front.** With nginx and OAuth2 Proxy
(connected to the bank's identity provider - Azure AD/Entra ID, Okta,
Keycloak, ADFS):

```nginx
server {
  listen 443 ssl;
  server_name credgate.bank.internal;
  # ssl_certificate ...;

  location /oauth2/ { proxy_pass http://127.0.0.1:4180; }
  location / {
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in;
    auth_request_set $user $upstream_http_x_auth_request_user;
    proxy_set_header X-Auth-Request-User $user;   # replaces anything the browser sent
    proxy_pass http://127.0.0.1:3838;
    proxy_http_version 1.1;                       # Shiny uses WebSockets
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
```

OAuth2 Proxy is started with `--set-xauthrequest` so it returns the user
(and their groups) in `X-Auth-Request-*` headers. Keycloak, or Apache with
`mod_auth_openidc`, work the same way: whatever signs people in passes the
name in a header that the app trusts (`trust_header`).

**3. Make the name match.** The name in the header must be the name in
`users.yaml` and `keys.json` - often the e-mail address or the directory
account name (`priya@bank.example` or `priya`).

## Roles and leavers from the directory (AD, LDAP)

`users.yaml` can be written by hand (`credgate users add ...`), or generated
from directory groups by a scheduled job, so joiners and leavers follow the
directory. For example, nightly from an AD group (using OpenLDAP's
`ldapsearch`):

```sh
#!/bin/sh
# users.yaml from AD groups: credgate-admins, credgate-auditors, credgate-users.
set -e
f=/srv/credgate/users.yaml.new
for role in admin auditor user; do
  ldapsearch -LLL -H ldaps://ad.bank.internal -b "dc=bank,dc=internal" \
    "(memberOf=CN=credgate-${role}s,OU=Groups,DC=bank,DC=internal)" sAMAccountName |
  awk '/^sAMAccountName:/ {print $2}' |
  while read -r name; do credgate users add "$name" --role "$role" --file "$f"; done
done
mv "$f" /srv/credgate/users.yaml    # replaced at once; the proxy and app reload it
```

Someone removed from the groups disappears from `users.yaml` at the next
run: the app shows them "No access", and the proxy refuses their key
("no longer has access") even before it expires. To cut access at once,
`credgate users deactivate <name> --file /srv/credgate/users.yaml`.

The **super admin** is whoever can run these commands on the server: there
is no super admin account in the app.

## Daily housekeeping

```sh
# keys not used for 60 days expire (judged from the audit log)
credgate proxy expire-unused --keys /srv/credgate/keys.json \
  --audit /srv/credgate/audit/audit-proxy1.jsonl --days 60
```

Audit logs rotate monthly and are pruned after the retention period
(`--audit-retention-years`, default 5). Back up `/srv/credgate`, keeping the
change and access logs: they are the evidence of who changed what.

## Several servers

Run the proxy on several servers behind a load balancer (health check
`GET /healthz`, which answers 503 while draining). Every instance needs the
same policy, keys and users files:

- **Shared storage** (NFS, a cluster file system) mounted at
  `/srv/credgate` on every server, with `--watch`: the app writes each file
  whole and renames it into place, so a proxy never reads half a file.
  Keep **one audit log per instance** (`audit-$(hostname).jsonl`): file
  locking is not reliable on network file systems.
- **Pushed files** (Ansible, Puppet, a Kubernetes ConfigMap and Secret):
  the app runs on one server and writes there; deployment copies the files
  to every instance and reloads them (`systemctl reload`, or `--watch`).

Either way, `/healthz` on each instance shows its policy revision, so you can
check that every instance has the new one. Give the app and the keys file
one home - the server the app runs on, or the shared storage - so that keys
are made in one place.

## Checklist

- [ ] The app listens on `127.0.0.1` and is reachable only through the
  sign-in proxy; `trust_header` names the header that proxy sets.
- [ ] TLS on the sign-in proxy and the credgate proxy (or the load balancer).
- [ ] Endpoint keys only in the proxy service's environment.
- [ ] `users.yaml` has at least one active admin; the super admin can reach
  the server's command line.
- [ ] The proxy runs with `--users`, `--watch` and `--require-tests`.
- [ ] Daily `expire-unused`; backups of `/srv/credgate`.
- [ ] Network rules make the proxy the only way to the external model
  endpoints.
