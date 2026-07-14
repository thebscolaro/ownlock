# GitHub Actions and repository security

This document describes how **ownlock** protects its CI/CD pipeline and what maintainers should verify in GitHub repository settings. See also [SECURITY.md](../SECURITY.md) for the product threat model.

## Workflow design

The only workflow is [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

| Property | Setting |
|----------|---------|
| Triggers | `push` / `pull_request` to `main`, and tags `v*` |
| `pull_request_target` | **Not used** — avoids running untrusted fork code with write permissions |
| Default `permissions` | `contents: read` |
| PyPI publish | OIDC (`id-token: write`) via `pypa/gh-action-pypi-publish`; no long-lived PyPI token in repo secrets |
| Publish gate | Requires `test`, `smoke`, `security`, and `build` jobs; tag push only |
| Release environment | `environment: pypi` — configure required reviewers in GitHub → Settings → Environments |
| Third-party actions | Pinned to full commit SHAs; Dependabot bumps the `github-actions` group weekly |

### Job permissions

| Job | Needs write? | Notes |
|-----|--------------|-------|
| `test` | No | Runs pytest; uploads coverage artifact |
| `smoke` | No | Subprocess CLI smoke tests |
| `security` | No | bandit + pip-audit |
| `build` | No | Builds sdist/wheel artifact |
| `publish` | `id-token: write` only | Downloads artifact, publishes to PyPI |

Fork pull requests do **not** receive repository secrets. Do not approve workflow runs from first-time contributors without reviewing the workflow diff.

## Repository settings checklist

Apply on `thebscolaro/ownlock` (Settings → General / Code security):

- [ ] **Branch protection** on `main`: require PR, require status checks (`test`, `smoke`, `security`, `build`), block force-push
- [ ] **Secret scanning** + **push protection** enabled
- [ ] **Dependabot alerts** enabled (pip + Actions)
- [ ] **Private vulnerability reporting** enabled (linked from SECURITY.md)
- [ ] **Actions permissions**: restrict to verified creators or allow only actions in this repo + marketplace verified publishers
- [ ] **Fork PR workflows**: require approval for outside collaborators
- [ ] **Environment `pypi`**: add required reviewers before production PyPI publish

Maintainers can script parts of this with `gh api` when authenticated.

## Supply-chain files

| File | Purpose |
|------|---------|
| `.github/dependabot.yml` | Weekly pip + github-actions update PRs |
| `.github/CODEOWNERS` | Review required for workflow, crypto, vault, share, pyproject |

## Reporting

Report workflow or CI vulnerabilities via [private security advisory](https://github.com/thebscolaro/ownlock/security/advisories/new).
