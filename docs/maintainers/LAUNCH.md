# Maintainer launch checklist

Public ops checklist for shipping ownlock (domain, distribution, outreach). No secrets belong here.

## Domain & site

- [ ] Register **ownlock.ai** (confirm standard ~$80–90/yr pricing, not premium)
- [ ] Cloudflare DNS + **Pages** project with root directory `website/` (see [website/README.md](../../website/README.md))
- [ ] Custom domain `ownlock.ai` (+ optional `www` → apex)
- [ ] Email Routing: `hello@`, `security@`, `press@` → maintainer inbox

## GitHub / CI

- [ ] Secret `DEVTO_API_KEY` for release announce workflow
- [ ] Optional variable `DEVTO_PUBLISH=true` (default creates Dev.to **drafts**)
- [ ] `pypi` environment reviewers for tagged publishes
- [ ] Repo settings in [github-security.md](../github-security.md)
- [ ] On each release tag: Release binaries workflow attaches Linux/macOS/Windows assets

## Distribution

- [ ] Interim Homebrew tap `thebscolaro/homebrew-ownlock` from [packaging/homebrew](../../packaging/homebrew)
- [ ] After Windows binary on the release: `scripts/fill_winget_sha.sh vX.Y.Z` → PR to `microsoft/winget-pkgs`
- [ ] Later: homebrew-core submission once notability criteria are met

## Outreach

Drafts live under [docs/blog/](../blog/). Paste manually:

- [ ] GitHub Release notes (canonical)
- [ ] Dev.to (automated draft on release if `DEVTO_API_KEY` is set)
- [ ] Show HN / Reddit / forums / social from the matching blog file
- [ ] Product Hunt reserved for a major milestone (0.3.0 or brew-core)

## Release cadence

- [ ] **0.3.0**: shield, guard, policies, team encrypted bundle (`team.olbundle`), providers
- [ ] After each tag: binaries + Dev.to draft + bump Homebrew formula url/sha/version
