# Contributing to credgate

## Branches and pull requests

`main` is always releasable. Nobody commits to it directly; every change,
including the maintainers', goes through a pull request.

1. Branch from an up-to-date `main`, named by the kind of change:
   `feat/…`, `fix/…`, `docs/…`, `chore/…` (tooling, CI, dependencies) or
   `release/…`. For example `feat/tokenise-restore`.
2. Open a pull request early (as a draft if it is not ready) and describe
   what changes and why.
3. CI (`nix flake check` on Linux and macOS) must pass. Run it locally first:

   ```bash
   nix flake check -L
   ```

4. The other maintainer reviews when possible. Address comments with new
   commits on the branch.
5. Merge with **squash and merge**, so `main` gets one commit per pull
   request, then delete the branch.

## Releases

Releases are cut from `main` only, after a `release/…` pull request is merged.

1. On `release/py-X.Y.Z` or `release/r-X.Y.Z`, bump the version
   (`pkg/python/pyproject.toml` and `src/credgate/__init__.py`, or
   `pkg/credgate/DESCRIPTION`) and update `pkg/python/CHANGELOG.md` or
   `pkg/credgate/NEWS.md`.
2. Merge the pull request once CI passes.
3. Tag the merge commit on `main`:
   - `py-vX.Y.Z` publishes to PyPI automatically (the `publish-pypi`
     workflow, Trusted Publishing).
   - `r-vX.Y.Z` marks the commit submitted to CRAN; the submission itself is
     made by the maintainer.
4. Update the pinned commit and versions in the Nix overlay.

Tags are never moved once a release is published.

## Conduct and security

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
Security issues are reported privately, as described in
[SECURITY.md](SECURITY.md) - never in a public issue.

## Rules that apply to every change

- **No real personal data**, anywhere: tests, examples, corpora, issues.
  Use synthetic data only.
- **Detection behaviour lives in `spec/`.** After changing it, run
  `tools/sync-spec.sh` and add or update conformance cases, so the R and
  Python engines stay identical.
- **Tests in both engines** for any behaviour change, and `ruff` clean for
  Python.
- **Secrets only from environment variables**, never in code or config.
