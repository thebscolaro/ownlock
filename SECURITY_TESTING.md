# Security testing

This document describes **what we automate**, how it maps to common categories (including OWASP Top 10–style concerns), and **what still requires humans** (pen tests, red team, formal threat modeling).

ownlock is a **local CLI** (plus optional stdio MCP). It is not a web app, so many OWASP entries apply only indirectly (e.g. “injection” as shell or path abuse, not SQL in a browser).

## Automated checks (run in CI and locally)

| Check | Tool | Purpose |
|--------|------|---------|
| **SAST (Python)** | [Bandit](https://github.com/PyCQA/bandit) | Static analysis for common Python issues; configured via `[tool.bandit]` in [pyproject.toml](pyproject.toml). Run: `bandit -r ownlock -c pyproject.toml` |
| **Dependency vulnerabilities** | [pip-audit](https://github.com/pypa/pip-audit) | Known CVEs in installed dependencies. Run after `pip install -e ".[mcp]"` (or full extras). CI upgrades pip before auditing. |

**pip-audit and editable installs:** If you install ownlock in **editable** mode (`pip install -e .`), pip-audit may skip CVE lookup for the **ownlock** package itself (it is not resolved like a PyPI wheel in that layout). Your **dependencies** (for example `cryptography`, `typer`, `keyring`) are still audited. A normal `pip install ownlock` from PyPI is fully included in the audit.
| **Regression tests** | pytest | [tests/test_security.py](tests/test_security.py) covers path traversal on **relative** paths, crypto/tamper behavior, invalid `vault()` keys, and **no shell** for subprocess helpers. |
| **Smoke / e2e CLI** | pytest (`-m smoke` or full suite) | [tests/test_smoke.py](tests/test_smoke.py) runs the real CLI in a subprocess with an isolated `HOME` and `OWNLOCK_PASSPHRASE` — closer to user installs than in-process CliRunner. |

Install dev tooling:

```bash
pip install -e ".[dev,mcp]"
bandit -r ownlock -c pyproject.toml
pip-audit
pytest tests/test_security.py -v
```

Bandit intentionally skips **B404** / **B603** for this repo: subprocess is required for `ownlock run` and MCP delegation; commands are passed as **argv lists**, not a shell string.

## OWASP Top 10 (2021) — rough mapping for ownlock

| ID | Theme | How we address it (design + tests) |
|----|--------|-------------------------------------|
| **A01** Broken access control | Path abuse | Relative `.env` / scan paths must stay **under cwd**; see `_validate_env_file` / `_validate_scan_dir` and tests. **Note:** Absolute paths are not sandboxed to cwd by design—users choose them explicitly. |
| **A02** Cryptographic failures | Vault at rest | AES-256-GCM, PBKDF2-SHA256 (200k iterations), per-encryption salt/nonce; wrong key / tamper → decrypt failure (tests). |
| **A03** Injection | Command / “template” injection | `ownlock run` uses `subprocess` with a **list** (no shell). Resolver allows only strict `vault("name")` syntax—not arbitrary code. |
| **A04** Insecure design | Trust boundaries | Documented in [SECURITY.md](SECURITY.md); MCP does not expose `get`/`export` and does not decrypt in the MCP process. |
| **A05** Misconfiguration | — | Keyring / `OWNLOCK_PASSPHRASE` left to the user; we document risks. |
| **A06** Vulnerable components | Supply chain | `pip-audit` in CI; pin minimum versions when advisories warrant (e.g. `cryptography`). |
| **A07–A10** Identification failures, integrity, logging, SSRF | Mostly N/A | No server, no OAuth in product; no SSRF surface in core CLI. |

This mapping is **informal**, not a certification.

## What “full” testing usually means (not replaced by CI)

| Activity | Role |
|----------|------|
| **Penetration test** | Skilled tester probes a **deployed** system end-to-end. ownlock has little network attack surface; value is higher for org-specific usage (policies, shared machines, CI secrets). |
| **Red team** | Simulated adversary against **people and processes** (phishing, workstation compromise), not just the binary. |
| **Bug bounty** | Rare for small OSS CLIs; optional if exposure grows. |
| **Threat modeling** | Structured review (STRIDE, data-flow diagrams). Useful before major features (e.g. remote sync). |

## Suggested cadence

- **Each release:** CI green (tests + Bandit + pip-audit).
- **Quarterly / after large changes:** Re-read [SECURITY.md](SECURITY.md), dependency audit, manual smoke of `init` / `run` / MCP.
- **Enterprise or high-risk environments:** Engage a third party for **formal** pen test / design review; bring your deployment model (laptops, CI, shared hosts).

## Reporting issues

See [SECURITY.md](SECURITY.md) for responsible disclosure.
