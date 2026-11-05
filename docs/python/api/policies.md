# Policies and audit log

::: credgate.Policy
::: credgate.Decision
::: credgate.PolicyMatch
::: credgate.Destination
::: credgate.PolicyError

## Saving policies and the change log

The same as R's `policy_write()`, `policy_diff()` and `policy_changes()`:
the same file layout and change log, so the R and Python policy editors
work on the same files.

::: credgate.write_policy
::: credgate.policy_diff
::: credgate.policy_changes
::: credgate.PolicyChanges
::: credgate.PolicyChange

## Policy tests

::: credgate.run_policy_tests
::: credgate.PolicyTestResult
::: credgate.policy_tests.write_policy_tests
::: credgate.policy_tests.test_from_decision

## Policy editor

Needs `pip install 'credgate[editor]'`; run it with `credgate editor`.

::: credgate.editor.policy_editor

## Audit log

::: credgate.AuditLog
::: credgate.audit_verify
::: credgate.audit_read
::: credgate.audit_prune
::: credgate.AuditCheck
::: credgate.audit.own_activity
