#!/usr/bin/env python3
"""Post a docs/blog markdown file to Dev.to via the Forem API.

Requires DEVTO_API_KEY in the environment (Settings → Extensions → DEV Community
API Keys). Defaults to creating a draft unless --publish is passed.

Usage:
  DEVTO_API_KEY=... python scripts/post_devto.py docs/blog/0.2.3-agent-shield.md
  DEVTO_API_KEY=... python scripts/post_devto.py docs/blog/0.2.3-agent-shield.md --publish
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

API_URL = "https://dev.to/api/articles"
DEFAULT_TAGS = ("python", "security", "opensource", "ai")


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Return (meta, body). Supports optional YAML-ish --- frontmatter."""
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text
    raw = text[4:end]
    body = text[end + 5 :]
    meta: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        meta[key.strip()] = val.strip().strip('"').strip("'")
    return meta, body


def _title_from_body(body: str, path: Path) -> str:
    for line in body.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem.replace("-", " ").title()


def _strip_outreach_sections(body: str) -> str:
    """Drop Show HN / tweet drafts that belong in the repo, not on Dev.to."""
    # Cut from a level-2 heading that looks like outreach collateral.
    pattern = re.compile(
        r"\n## (Show HN|Tweet thread|Reddit|Lobsters|Posting notes).*\Z",
        re.IGNORECASE | re.DOTALL,
    )
    return pattern.sub("\n", body).rstrip() + "\n"


def post_article(
    *,
    path: Path,
    api_key: str,
    published: bool,
    series: str | None,
    canonical_url: str | None,
) -> dict:
    text = path.read_text(encoding="utf-8")
    meta, body = _parse_frontmatter(text)
    body = _strip_outreach_sections(body)
    title = meta.get("title") or _title_from_body(body, path)
    description = meta.get("description") or title
    tags_raw = meta.get("tags") or ",".join(DEFAULT_TAGS)
    tags = [t.strip() for t in tags_raw.replace(",", " ").split() if t.strip()][:4]

    payload = {
        "article": {
            "title": title,
            "body_markdown": body,
            "published": published,
            "description": description[:200],
            "tags": tags,
        }
    }
    if series or meta.get("series"):
        payload["article"]["series"] = series or meta["series"]
    if canonical_url or meta.get("canonical_url"):
        payload["article"]["canonical_url"] = canonical_url or meta["canonical_url"]

    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "api-key": api_key,
            "User-Agent": "ownlock-release-bot",
            "Accept": "application/vnd.forem.api-v1+json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Dev.to API error {e.code}: {detail}") from e


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Markdown file under docs/blog/")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish immediately (default: create as draft for review).",
    )
    parser.add_argument("--series", default=None, help="Optional Dev.to series name.")
    parser.add_argument(
        "--canonical-url",
        default=None,
        help="Canonical URL (e.g. GitHub release or ownlock.ai post).",
    )
    args = parser.parse_args()

    api_key = os.environ.get("DEVTO_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("DEVTO_API_KEY is not set")
    if not args.path.is_file():
        raise SystemExit(f"File not found: {args.path}")

    result = post_article(
        path=args.path,
        api_key=api_key,
        published=args.publish,
        series=args.series,
        canonical_url=args.canonical_url,
    )
    url = result.get("url") or result.get("path")
    status = "published" if args.publish else "draft"
    print(f"Dev.to {status}: {url}")
    print(json.dumps({"id": result.get("id"), "url": url, "published": args.publish}))


if __name__ == "__main__":
    main()
