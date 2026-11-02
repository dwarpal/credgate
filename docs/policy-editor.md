# Policy editor

The policy editor is a small web app (R Shiny) that lets InfoSec change a
policy without editing YAML by hand. It shows the policy's endpoints and its
rules in order. You can try a sample text against any endpoint. It shows what
changed before you save, and keeps a history of every save: who saved it,
when, why, and what changed. It has light and dark themes (following the
system setting, with a switch in the header), works on narrow screens, and
explains every field in a tooltip. It loads nothing from the internet, so it
runs on air-gapped machines.

![The policy editor: endpoints by tier, with a summary of the policy](images/policy-editor/endpoints.png)

```r
# install.packages(c("shiny", "bslib"))
credgate::policy_editor("bank-default.yaml", user = "infosec-1")
```

## What it does

| Rules, in the order they are checked | Try it: what a model would receive |
|---|---|
| ![Rules](images/policy-editor/rules.png) | ![Try it, redacted](images/policy-editor/try-redacted.png) |
| **Try it, blocked** (dark theme) | **Changes and the change log** |
| ![Try it, blocked](images/policy-editor/try-blocked.png) | ![Changes](images/policy-editor/changes.png) |

- **Endpoints**: add, change, block or remove the model endpoints that
  requests may go to. An endpoint that a rule still names cannot be removed.
  If you rename an endpoint, the rules that name it are updated too.
- **Rules**: add, change, remove and reorder rules. The first rule that
  matches decides the action, so order matters. Move a rule up or down to
  change it.
- **Try it**: paste a sample text (use synthetic data), pick an endpoint and
  see what the unsaved policy would decide, and which rule decided it.
  Detected values are shown masked.
- **Changes**: what is different from the saved file, and the history of
  saves. The history is hash-chained like the audit log, so an entry that was
  edited or removed afterwards shows as broken.

**Save** stays disabled until the policy is valid and has changes. The
policy is checked exactly as the proxy loads it, so the editor can never save
a policy that the proxy would refuse. Each save raises the policy's
`revision` by one. The proxy and the audit log record that revision with
every decision.

## Files

| File | What it holds |
|---|---|
| `bank-default.yaml` | The policy, written in a fixed layout |
| `bank-default.changes.jsonl` | One line per save: time, user, note, revisions, changes |

Comments in a policy file are **not kept** when the editor saves it. Put
explanations in the `description` fields of the policy, its endpoints and
its rules, which are kept.

From R, without the app:

```r
policy <- yaml::read_yaml("bank-default.yaml")
policy$destinations$copilot$blocked <- FALSE
policy_diff(yaml::read_yaml("bank-default.yaml"), policy)
policy_write(policy, "bank-default.yaml", user = "infosec-1", note = "Copilot approved")
policy_changes("bank-default.yaml")
```

## Running it for a team

On Shiny Server or Posit Connect, put this in an `app.R`:

```r
credgate::policy_editor("/srv/credgate/bank-default.yaml",
                        user = Sys.getenv("SHINYPROXY_USERNAME", "unknown"))
```

Without `user`, the editor fills in the signed-in user that Shiny reports
(`session$user`), or else the operating-system account. The name field stays
editable, so treat it as a record of who said they saved it. Rely on the
server's sign-in to control who can reach the app. Only people allowed to change the
policy should be able to reach the app. It writes the policy file, so run
it under an account that can write that file and nothing else.

The proxy reads the policy when it starts. Restart it (or its workers
behind the load balancer, one at a time) to apply a saved change.
