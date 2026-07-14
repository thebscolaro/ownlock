# Don't replace 1Password — broker it

ownlock is a **local secret broker**, not a team SaaS competitor.

Keep 1Password or AWS Secrets Manager as source of truth; reference them from `.env`:

```dotenv
API_KEY=vault("op://vault/item/credential")
DB_PASSWORD=vault("aws-sm://prod/db#password")
```

ownlock resolves these at runtime via the local `op` and `aws` CLIs, then applies:

- per-secret policies (`confirm` / `session` / `open`)
- stdout redaction in `ownlock run`
- agent shield + guard
- audit log with agent attribution

You get one injection path for humans, agents, and CI — without migrating off the vault you already pay for.
