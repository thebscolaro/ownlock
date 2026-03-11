# Security

## Reporting vulnerabilities

If you discover a security vulnerability in ownlock, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Email the maintainers or open a [private security advisory](https://github.com/thebscolaro/ownlock/security/advisories/new) on GitHub.
3. Include a description of the vulnerability, steps to reproduce, and any suggested fixes.
4. We will respond promptly and work with you to address the issue.

## Security model

- **Encryption**: Secrets are encrypted with AES-256-GCM before storage. Key derivation uses PBKDF2-HMAC-SHA256 with 200,000 iterations.
- **Passphrase**: Stored in the system keyring (macOS Keychain, GNOME Keyring) when possible. Can also be provided via `OWNLOCK_PASSPHRASE` or interactively.
- **No network**: ownlock never makes network requests. All data stays local.
- **Path safety**: Relative paths for `.env` files and scan directories are validated to stay within the current directory.
- **Subprocess**: `ownlock run` passes the command as a list to the OS exec APIs. No shell interpretation. Secrets are injected as environment variables.
- **Redaction**: Known secret values are replaced with `[REDACTED:NAME]` in subprocess stdout/stderr.

## Known limitations

- Decrypted secrets exist in process memory while commands run.
- Environment variables are visible to child processes and can appear in process listings.
- The system keyring can be accessed by other applications running as the same user.
