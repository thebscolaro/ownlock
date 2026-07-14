# ownlock.ai website

Static marketing site for [ownlock.ai](https://ownlock.ai).

## Local preview

```bash
cd website
python3 -m http.server 8080
# open http://127.0.0.1:8080
```

## Deploy on Cloudflare Pages

1. Buy **ownlock.ai** (Porkbun / Cloudflare Registrar / Namecheap — expect ~$83/yr for `.ai`).
2. In Cloudflare: **Workers & Pages** → **Create** → connect `thebscolaro/ownlock`.
3. Build settings:
   - **Framework preset:** None
   - **Root directory:** `website`
   - **Build command:** (empty)
   - **Build output directory:** `/` (or leave as root of the configured project directory)
4. After the first deploy, **Custom domains** → add `ownlock.ai` (and optional `www` → redirect to apex).
5. **Email** → Email Routing: create `hello@ownlock.ai` and `security@ownlock.ai` → forward to your inbox.

`CNAME` in this folder is set to `ownlock.ai` for GitHub Pages compatibility; Cloudflare Pages uses the custom domain UI instead and ignores this file unless you also publish via GitHub Pages.

## Design notes

Charcoal surface, signal-green accent, Syne + IBM Plex. Hero is full-bleed SVG atmosphere + brand-first wordmark — no feature-card wall in the first viewport.
