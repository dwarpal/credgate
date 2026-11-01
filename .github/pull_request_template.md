## What and why

<!-- What changes, and the problem it solves. -->

## Checklist

- [ ] Behaviour changes are in the spec (`spec/`) first, synced with `tools/sync-spec.sh`, with conformance cases
- [ ] R and Python both implement it and pass the same conformance cases
- [ ] Tests added or updated; `nix flake check -L` passes locally
- [ ] Changelogs updated (`pkg/python/CHANGELOG.md`, `pkg/credgate/NEWS.md`) and docs, if users see the change
- [ ] Only synthetic data anywhere (tests, examples, screenshots, this description)
- [ ] No secrets, keys or passphrases; nothing that would make credgate use the network
