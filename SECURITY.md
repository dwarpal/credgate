# Security policy

credgate protects personal data, so security reports matter. Thank you for
taking the time to report one.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately instead:

1. Preferred: GitHub's private reporting - the **Report a vulnerability**
   button on the repository's **Security** tab.
2. Or email the maintainers: bharat8sikka@gmail.com and
   aishwarya.bais00@gmail.com.

Include what you found, how to reproduce it (with **synthetic data only** -
never real personal data), and the version you used. We acknowledge reports
within 5 working days, keep you informed, and credit you in the release
notes unless you prefer otherwise.

## What counts

Examples of what we treat as security issues:

- personal data reaching a destination its policy forbids (for example a
  policy `block` or `redact` not applied), or detection silently skipped;
- values, tokens or keys appearing where they must not: printed output,
  logs, audit records, error messages;
- weaknesses in saved vault files, keyed tokens or the audit log's tamper
  evidence;
- any network access by credgate (it must run fully offline);
- problems in the release or supply chain.

A single identifier that detection misses is usually an accuracy issue,
not a vulnerability: open a normal issue with a synthetic example, unless
the miss is systematic or exploitable.

The [threat model](docs/threat-model.md) describes what credgate does and
does not protect against.

## Supported versions

Security fixes go into the latest release of each package: the Python
package on PyPI and the R package on CRAN and R-universe. Please upgrade
before reporting.
