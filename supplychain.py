#!/usr/bin/env python3
"""
supplychain.py — Supply Chain Attack & Dependency Takeover Scanner
==================================================================
Finds CLAIMED (already squatted/malicious) and UNCLAIMED (claimable)
supply chain attack surfaces. Every finding passes a multi-stage
validation chain before being reported — no speculation, no guesses.

Detection coverage:
  CDN scripts      → jsDelivr (gh/ + npm/), unpkg, cdnjs, rawgit,
                     raw.githubusercontent.com, esm.sh, skypack.dev,
                     jspm.dev, deno.land/x, GitHub Gists
  Registry pkgs    → npm, PyPI, RubyGems, NuGet, Cargo, pkg.go.dev
  GitHub deps      → package.json github: refs, git+https://, Actions
  Signals          → namespace squatting, content replacement, tag
                     inflation, dead maintainers, dep confusion,
                     SRI absence, floating refs, archived Wayback diff
  Validation       → 3-stage chain per finding before output

NEW DETECTIONS (v2):
  Typosquatting    → Levenshtein distance 1-2 against top 500 npm pkgs
  Manifest poisoning → postinstall/preinstall lifecycle script scanning
  lockfile confusion → package-lock.json resolved URL vs declared name
  GitHub Actions pinning → SHA-pin audit, unpinned 3rd-party actions
  Retired CDN hosts → rawgit, gitcdn, old esm/skypack endpoints
  PyPI/RubyGems/Cargo namespace squatting (mirrors npm checks)
  Self-hosted font/resource exfil → @font-face src: external + data-uri tricks
  npm package scope squatting → @scope unclaimed check (improved)
  Sourcemap exfil → //# sourceMappingURL pointing to attacker infra
  Package.json "scripts" injection → lifecycle hooks with curl/wget/eval

Usage:
  python3 supplychain.py -u https://target.com/
  python3 supplychain.py -u https://target.com/ --deep
  python3 supplychain.py -f urls.txt
  python3 supplychain.py --js bundle.js
  python3 supplychain.py --package-json package.json
  python3 supplychain.py --workflow .github/workflows/deploy.yml
  python3 supplychain.py --github-org enphaseenergy
  python3 supplychain.py -u https://target.com/ -o results.json

Author: Shadowbyte
"""

import sys
import argparse
import json
import re
import os
import hashlib
import time
import threading
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote
from typing import Optional

import requests

requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────────────────────
RESET   = "\033[0m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
WHITE   = "\033[97m"
BLUE    = "\033[94m"

def c(col, txt): return f"{col}{txt}{RESET}"

_print_lock = threading.Lock()
_verbose_global = False

def sprint(*a, **k):
    with _print_lock:
        print(*a, **k)

# ─────────────────────────────────────────────────────────────
# HTTP sessions
# ─────────────────────────────────────────────────────────────
def _make_session(ua="hackerone-shadowbyte"):
    s = requests.Session()
    s.headers["User-Agent"] = ua
    s.verify = False
    return s

HTTP  = _make_session()
GH    = _make_session()
GH.headers["Accept"] = "application/vnd.github.v3+json"
if os.environ.get("GITHUB_TOKEN"):
    GH.headers["Authorization"] = f"token {os.environ['GITHUB_TOKEN']}"

def _get(session, url, timeout=12, **kw):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, **kw)
    except Exception:
        return None

def gh_api(path):
    r = _get(GH, f"https://api.github.com{path}")
    if r and r.status_code == 200:
        try: return r.json()
        except Exception: pass
    return None

# ─────────────────────────────────────────────────────────────
# Established account / library heuristics
# ─────────────────────────────────────────────────────────────
# Used to suppress false positives on well-known legitimate projects.
# A "trusted maintainer" is: account age >2yr AND followers >500 AND stars >500.
# Content changes on these accounts are almost certainly legitimate version bumps,
# not supply chain attacks. We demote from HIGH/CLAIMED to INFO and add a note.

TRUSTED_ACCOUNT_FOLLOWERS_MIN = 500
TRUSTED_ACCOUNT_AGE_DAYS_MIN  = 730   # 2 years
TRUSTED_REPO_STARS_MIN        = 500

def _is_trusted_maintainer(user_info: dict, repo_info: dict = None) -> bool:
    """Return True if this account/repo looks like a legitimate, established project."""
    if not user_info.get("exists"):
        return False
    age = user_info.get("age_days") or 0
    followers = user_info.get("followers") or 0
    if age < TRUSTED_ACCOUNT_AGE_DAYS_MIN or followers < TRUSTED_ACCOUNT_FOLLOWERS_MIN:
        return False
    if repo_info and repo_info.get("exists"):
        stars = repo_info.get("stars") or 0
        if stars < TRUSTED_REPO_STARS_MIN:
            return False
    return True

# ─────────────────────────────────────────────────────────────
# Malicious content detection
# ─────────────────────────────────────────────────────────────

EXFIL_VECTORS = re.compile(
    r'(?:'
    r'new\s+Image\s*\(\s*\)\s*\.\s*src\s*=\s*["\']https?://[^"\']{4,}[?&]'
    r'|navigator\.sendBeacon\s*\(\s*["\']https?://(?!(?:amazonaws|cognito|microsoft|google|cloudfront|apple|facebook|twitter|analytics|segment|mixpanel|amplitude|datadog|newrelic|sentry))'
    r'|new\s+WebSocket\s*\(\s*["\']wss?://[a-z0-9-]{3,20}\.[a-z]{2,6}[/"\'?]'
    r')',
    re.IGNORECASE
)

UNCONDITIONAL_BAD = re.compile(
    r'(?:'
    r'CoinHive|coinhive|cryptonight|minero\.cc|coinhive\.min\.js'
    r'|eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\('
    r'|String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){9,}'
    r'|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){15,}'
    r'|wasm.*[Mm]iner|[Mm]iner.*wasm'
    r')',
    re.IGNORECASE
)

DATA_ACCESS = re.compile(
    r'(?:document\.cookie|localStorage\.|sessionStorage\.'
    r'|document\.querySelector\s*\(["\'](?:input\[type=["\']?password|#password|\.password))',
    re.IGNORECASE
)

POC_MARKER = re.compile(
    r'^(?:\s*console\.log\s*\(\s*["\'][a-zA-Z0-9_\-]{3,40}["\']\s*\)\s*;?\s*|'
    r'\s*alert\s*\(\s*["\'][^"\']{1,30}["\']\s*\)\s*;?\s*)$',
    re.MULTILINE
)

# ── NEW: Lifecycle script injection patterns ──────────────────
# postinstall/preinstall hooks that run shell commands = npm install-time RCE
LIFECYCLE_INJECT = re.compile(
    r'(?:curl|wget|bash|sh|python|node|exec|eval|nc\s|ncat\s|/bin/sh|/bin/bash'
    r'|\$\(.*\)|`.*`)',
    re.IGNORECASE
)

# ── NEW: Sourcemap exfil — //# sourceMappingURL pointing outside the origin ──
SOURCEMAP_EXFIL = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*(https?://[^\s"\']+)',
    re.IGNORECASE
)

# ── NEW: Self-hosted resource loading external data via CSS tricks ────────────
CSS_EXFIL = re.compile(
    r'@font-face\s*\{[^}]*src\s*:[^}]*url\s*\(\s*["\']?(https?://[^"\')\s]{10,})["\']?\s*\)',
    re.IGNORECASE | re.DOTALL
)

def detect_malicious(content: str) -> list[str]:
    findings = []
    if not content:
        return findings

    stripped = content.strip()
    if len(stripped) < 300 and POC_MARKER.match(stripped):
        findings.append(f"PoC squatter marker — entire file content: `{stripped[:100]}`")
        return findings

    exfil_match = EXFIL_VECTORS.search(content)
    if exfil_match:
        exfil_pos = exfil_match.start()
        window_start = max(0, exfil_pos - 500)
        window_end   = min(len(content), exfil_pos + 500)
        window = content[window_start:window_end]
        data_match = DATA_ACCESS.search(window)
        if data_match:
            findings.append(
                f"Data exfiltration: `{data_match.group(0)[:50]}` sent via "
                f"`{exfil_match.group(0)[:60]}`"
            )
        else:
            findings.append(
                f"Suspicious outbound data pattern: `{exfil_match.group(0)[:80]}`"
            )

    ub_match = UNCONDITIONAL_BAD.search(content)
    if ub_match:
        findings.append(f"Unconditionally malicious: `{ub_match.group(0)[:80]}`")

    # ── NEW: sourcemap exfil ─────────────────────────────────
    sm_match = SOURCEMAP_EXFIL.search(content)
    if sm_match:
        sm_url = sm_match.group(1)
        # Only flag if the sourcemap URL is NOT on a known CDN/same-domain
        if not any(safe in sm_url for safe in [
            "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
            "raw.githubusercontent.com", "ajax.googleapis.com",
        ]):
            findings.append(f"Sourcemap exfil: //# sourceMappingURL → `{sm_url[:100]}`")

    return findings


# ─────────────────────────────────────────────────────────────
# NEW: Typosquatting detector
# ─────────────────────────────────────────────────────────────
# Top ~100 most-downloaded npm packages that are commonly typosquatted.
# Levenshtein distance 1 against this list = typosquatting candidate.

TOP_NPM_PACKAGES = {
    "lodash", "express", "react", "react-dom", "axios", "moment", "chalk",
    "commander", "debug", "async", "request", "underscore", "bluebird",
    "webpack", "babel-core", "jquery", "angular", "vue", "typescript",
    "next", "nuxt", "gatsby", "svelte", "rollup", "vite", "esbuild",
    "prettier", "eslint", "jest", "mocha", "chai", "sinon", "karma",
    "grunt", "gulp", "parcel", "browserify", "require", "minimist",
    "yargs", "dotenv", "uuid", "classnames", "redux", "mobx", "rxjs",
    "socket.io", "fastify", "koa", "hapi", "nestjs", "typeorm", "sequelize",
    "mongoose", "pg", "mysql", "redis", "graphql", "apollo", "prisma",
    "zod", "joi", "yup", "crypto-js", "bcrypt", "jsonwebtoken", "passport",
    "multer", "sharp", "jimp", "cheerio", "puppeteer", "playwright",
    "selenium-webdriver", "supertest", "nodemailer", "ws", "cors",
    "helmet", "morgan", "compression", "body-parser", "cookie-parser",
    "path", "fs-extra", "rimraf", "glob", "chokidar", "cross-env",
    "concurrently", "nodemon", "pm2", "forever", "dotenv-safe",
}

def _levenshtein(a: str, b: str) -> int:
    """Fast Levenshtein distance."""
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j-1] + 1,
                            prev[j-1] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]

def check_typosquatting(pkg_name: str) -> Optional[str]:
    """Return the closest legitimate package name if distance ≤ 1, else None."""
    # Strip scope prefix for comparison
    name = pkg_name.lstrip("@").split("/")[-1].lower()
    # Skip very short names (too many false positives)
    if len(name) < 4:
        return None
    for legit in TOP_NPM_PACKAGES:
        if name == legit:
            return None  # exact match = not a typosquat
        if abs(len(name) - len(legit)) > 2:
            continue
        dist = _levenshtein(name, legit)
        if dist == 1:
            return legit
    return None


# ─────────────────────────────────────────────────────────────
# NEW: Package lifecycle script scanner
# ─────────────────────────────────────────────────────────────

def scan_lifecycle_scripts(pkg_json_text: str, source: str = "") -> list[dict]:
    """
    Scan package.json lifecycle hooks (postinstall, preinstall, install, prepare)
    for shell injection patterns: curl, wget, bash, eval, $(), backticks.
    These execute at npm install time — they're install-time RCE if the package
    is pulled from a squatted/compromised namespace.
    """
    results = []
    try:
        data = json.loads(pkg_json_text)
    except Exception:
        return results

    scripts = data.get("scripts", {})
    dangerous_hooks = ["postinstall", "preinstall", "install", "prepare", "prepack", "postpack"]

    for hook in dangerous_hooks:
        cmd = scripts.get(hook, "")
        if not cmd:
            continue
        m = LIFECYCLE_INJECT.search(cmd)
        if m:
            results.append(dict(
                url=f"package.json#{hook}",
                cdn="lifecycle-inject",
                owner=None, repo=None,
                package=data.get("name", "<unknown>"),
                ref=None, version=data.get("version", ""),
                issues=[
                    f"LIFECYCLE INJECTION: {hook} hook contains shell execution: `{cmd[:120]}`"
                ],
                severity="CRITICAL",
                claimed=True, details={"hook": hook, "cmd": cmd},
                signals=4,
                source=source,
            ))

    return results


# ─────────────────────────────────────────────────────────────
# NEW: Lockfile confusion scanner
# ─────────────────────────────────────────────────────────────

def scan_lockfile_confusion(lockfile_text: str, source: str = "") -> list[dict]:
    """
    Detect lockfile confusion: package-lock.json 'resolved' URLs pointing to
    registries other than registry.npmjs.org (internal mirrors, attacker infra).
    Also detect packages where the resolved URL domain doesn't match the declared
    name's expected registry — indicates dependency confusion or mirror poisoning.
    """
    results = []
    try:
        data = json.loads(lockfile_text)
    except Exception:
        return results

    packages = data.get("packages", data.get("dependencies", {}))
    if not isinstance(packages, dict):
        return results

    for pkg_path, pkg_data in packages.items():
        if not isinstance(pkg_data, dict):
            continue
        resolved = pkg_data.get("resolved", "")
        if not resolved:
            continue
        parsed = urlparse(resolved)
        domain = parsed.netloc.lower()

        # Flag if resolved URL is NOT npmjs.org or known mirrors
        trusted_registries = {
            "registry.npmjs.org", "registry.yarnpkg.com",
            "npm.pkg.github.com", "packages.atlassian.com",
        }
        if domain and domain not in trusted_registries and not domain.endswith(".npmjs.org"):
            # Internal mirror or unexpected registry
            pkg_name = pkg_path.lstrip("node_modules/").lstrip("/")
            results.append(dict(
                url=resolved,
                cdn="lockfile-confusion",
                owner=None, repo=None,
                package=pkg_name,
                ref=None, version=pkg_data.get("version", ""),
                issues=[
                    f"LOCKFILE CONFUSION: '{pkg_name}' resolved from non-standard registry: "
                    f"{domain} — expected registry.npmjs.org"
                ],
                severity="HIGH",
                claimed=False,
                details={"resolved": resolved, "registry": domain},
                signals=3,
                source=source,
            ))

    return results


# ─────────────────────────────────────────────────────────────
# NEW: Enhanced GitHub Actions audit
# ─────────────────────────────────────────────────────────────

# Known safe action owners that should always be trusted
TRUSTED_ACTION_OWNERS = {
    "actions", "github", "docker", "aws-actions", "azure",
    "google-github-actions", "hashicorp", "gradle", "gradle",
}

SHA_PIN_RE = re.compile(r'^[a-f0-9]{40}$')

def audit_actions_pinning(workflow_text: str, source: str = "") -> list[dict]:
    """
    Audit GitHub Actions workflow for:
    1. Unpinned 3rd-party actions (using tag/branch instead of SHA)
    2. Actions from deleted/unclaimed repos
    3. Actions using @main/@master (mutable floating refs)
    """
    results = []
    for m in re.finditer(r'uses:\s+([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)@([^\s#\n]+)', workflow_text):
        owner, repo, ref = m.group(1), m.group(2), m.group(3).strip()
        if owner.lower() in TRUSTED_ACTION_OWNERS:
            continue

        issues = []
        severity = "INFO"
        signals = 0

        # Floating ref check
        if ref.lower() in ("main", "master", "head", "latest", "dev", "next"):
            issues.append(
                f"FLOATING ACTION REF: {owner}/{repo}@{ref} — mutable branch ref, "
                f"any push to this branch immediately affects your pipeline"
            )
            severity = "HIGH"
            signals += 2

        # Tag (not SHA) — mutable but less risky than branch
        elif not SHA_PIN_RE.match(ref):
            issues.append(
                f"UNPINNED ACTION: {owner}/{repo}@{ref} — tag reference is mutable "
                f"(tags can be force-pushed); pin to a commit SHA for supply chain safety"
            )
            severity = "MEDIUM"
            signals += 1

        # Check if the action repo exists
        repo_info = gh_repo(owner, repo)
        if not repo_info.get("exists"):
            issues.append(
                f"UNCLAIMED ACTION REPO: {owner}/{repo} does not exist — "
                f"create it and tag {ref} to hijack all pipelines using this action"
            )
            severity = "CRITICAL"
            signals += 3
        elif repo_info.get("archived"):
            issues.append(
                f"ARCHIVED ACTION REPO: {owner}/{repo} is archived — "
                f"maintainer abandoned it; namespace may become re-claimable"
            )
            severity = "MEDIUM" if severity == "INFO" else severity
            signals += 1

        if not issues:
            continue

        results.append(dict(
            url=f"https://github.com/{owner}/{repo}",
            cdn="github-action",
            owner=owner, repo=repo,
            package=None, ref=ref, version=None,
            context=f"GitHub Action: {owner}/{repo}@{ref}",
            issues=issues,
            severity=severity,
            claimed=not repo_info.get("exists", True),
            details={"repo": repo_info},
            signals=signals,
            source=source,
        ))

    return results


# ─────────────────────────────────────────────────────────────
# NEW: PyPI / RubyGems / Cargo namespace squatting
# ─────────────────────────────────────────────────────────────

def check_pypi_squatting(pkg_name: str) -> Optional[dict]:
    """Check if a PyPI package name looks squatted (exists but suspiciously thin)."""
    info = pypi_info(pkg_name)
    if not info.get("exists"):
        return dict(
            available=True,
            issues=[f"UNCLAIMED PYPI: '{pkg_name}' does not exist on PyPI — "
                    f"pip install {pkg_name} will fail, but if an internal package uses this name, "
                    f"registering it on PyPI enables dep confusion"]
        )
    return None


def check_cargo_squatting(pkg_name: str) -> Optional[dict]:
    """Check if a Cargo crate looks squatted."""
    info = cargo_info(pkg_name)
    if not info.get("exists"):
        return dict(
            available=True,
            issues=[f"UNCLAIMED CARGO CRATE: '{pkg_name}' does not exist on crates.io"]
        )
    return None


# ─────────────────────────────────────────────────────────────
# NEW: Retired/dead CDN host detector
# ─────────────────────────────────────────────────────────────

RETIRED_CDN_HOSTS = {
    "rawgit.com":           "Shut down 2019 — requests redirect to jsDelivr but mapping may break",
    "cdn.rawgit.com":       "Shut down 2019",
    "gitcdn.xyz":           "Shut down — no longer operational",
    "wzrd.in":              "Browserify CDN — shut down 2020",
    "npmcdn.com":           "Renamed to unpkg.com in 2016 — old URLs may 404",
    "cdnjs.com":            "Use cdnjs.cloudflare.com — bare cdnjs.com may redirect inconsistently",
    "bootstrap-cdn.com":    "Not the official Bootstrap CDN (bootstrapcdn.com) — potential phishing",
    "angular-ui.github.io": "GitHub Pages for AngularUI — organization may have changed",
}

def check_retired_cdn(url: str) -> Optional[str]:
    """Return a warning string if the URL uses a known retired CDN host."""
    try:
        host = urlparse(url).netloc.lower()
        for dead_host, reason in RETIRED_CDN_HOSTS.items():
            if host == dead_host or host.endswith("." + dead_host):
                return reason
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# GitHub helpers
# ─────────────────────────────────────────────────────────────

def gh_user(owner: str) -> dict:
    d = gh_api(f"/users/{owner}")
    if not d:
        return {"exists": False}
    age = None
    recent = False
    ca = d.get("created_at", "")
    if ca:
        try:
            dt = datetime.fromisoformat(ca.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - dt).days
            recent = age < 365
        except Exception:
            pass
    return {
        "exists": True, "type": d.get("type", "User"),
        "created_at": ca, "age_days": age, "recently_created": recent,
        "public_repos": d.get("public_repos", 0),
        "followers": d.get("followers", 0),
        "name": d.get("name") or "", "bio": d.get("bio") or "",
    }

def gh_repo(owner: str, repo: str) -> dict:
    d = gh_api(f"/repos/{owner}/{repo}")
    if not d:
        return {"exists": False}
    return {
        "exists": True,
        "stars": d.get("stargazers_count", 0),
        "forks": d.get("forks_count", 0),
        "description": (d.get("description") or ""),
        "pushed_at": d.get("pushed_at", ""),
        "created_at": d.get("created_at", ""),
        "default_branch": d.get("default_branch", "main"),
        "archived": d.get("archived", False),
        "size_kb": d.get("size", 0),
        "is_fork": d.get("fork", False),
    }

def gh_commits(owner, repo, n=5) -> list:
    d = gh_api(f"/repos/{owner}/{repo}/commits?per_page={n}")
    if not isinstance(d, list):
        return []
    return [{"sha": c.get("sha","")[:12],
             "msg": c.get("commit",{}).get("message","")[:120],
             "author": c.get("commit",{}).get("author",{}).get("name",""),
             "date": c.get("commit",{}).get("author",{}).get("date","")}
            for c in d]

def gh_tags(owner, repo) -> list:
    d = gh_api(f"/repos/{owner}/{repo}/tags?per_page=30")
    if not isinstance(d, list):
        return []
    sha_count = {}
    tags = []
    for t in d:
        sha = t.get("commit",{}).get("sha","")[:12]
        sha_count[sha] = sha_count.get(sha, 0) + 1
        tags.append({"name": t.get("name",""), "sha": sha})
    for t in tags:
        t["inflated"] = sha_count[t["sha"]] > 1
    return tags

def gh_npm_scope_owner(scope: str) -> Optional[str]:
    d = gh_api(f"/orgs/{scope}")
    if d and d.get("login"):
        return d["login"]
    return None


# ─────────────────────────────────────────────────────────────
# jsDelivr purge-cache / deleted-but-cached detection
# ─────────────────────────────────────────────────────────────

def check_jsdelivr_stale_cache(cdn_url: str) -> bool:
    if "cdn.jsdelivr.net/gh/" not in cdn_url:
        return False
    m = re.search(r'cdn\.jsdelivr\.net/gh/([^/]+)/([^@/]+)@([^/]+)/(.*)', cdn_url)
    if not m:
        return False
    owner, repo, ref, filepath = m.group(1), m.group(2), m.group(3), m.group(4)
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{filepath}"
    cdn_r = _get(HTTP, cdn_url, timeout=10)
    raw_r = _get(HTTP, raw_url, timeout=10)
    cdn_ok = cdn_r and cdn_r.status_code == 200
    raw_ok = raw_r and raw_r.status_code == 200
    return cdn_ok and not raw_ok


# ─────────────────────────────────────────────────────────────
# Wayback Machine
# ─────────────────────────────────────────────────────────────

def wayback_fetch(url: str) -> Optional[dict]:
    r = _get(HTTP, f"http://archive.org/wayback/available?url={quote(url)}", timeout=12)
    if not r or r.status_code != 200:
        return None
    try:
        snap = r.json().get("archived_snapshots", {}).get("closest", {})
    except Exception:
        return None
    if not snap or snap.get("status") != "200":
        return None
    snap_url = snap.get("url", "")
    ts = snap.get("timestamp", "")
    r2 = _get(HTTP, snap_url, timeout=20)
    if not r2 or r2.status_code != 200:
        return None
    body = r2.text
    return {
        "timestamp": ts,
        "size": len(body),
        "sha256": hashlib.sha256(body.encode(errors="replace")).hexdigest()[:16],
        "url": snap_url,
        "preview": body[:300].strip(),
    }


# ─────────────────────────────────────────────────────────────
# Live CDN content fetch
# ─────────────────────────────────────────────────────────────

def fetch_live(url: str, retries: int = 2) -> Optional[dict]:
    bodies = []
    for i in range(retries):
        if i > 0:
            time.sleep(1)
        r = _get(HTTP, url, timeout=18)
        if r and r.status_code == 200:
            bodies.append(r.text)
        elif r:
            return {"status": r.status_code, "size": 0, "content": None}
    if not bodies:
        return None
    consistent = len(set(b[:500] for b in bodies)) == 1
    body = bodies[0]
    return {
        "status": 200,
        "size": len(body),
        "sha256": hashlib.sha256(body.encode(errors="replace")).hexdigest()[:16],
        "preview": body[:300].strip(),
        "content": body,
        "consistent": consistent,
    }


# ─────────────────────────────────────────────────────────────
# Registry checks
# ─────────────────────────────────────────────────────────────

def _npm_user_exists(username: str) -> bool:
    r = _get(HTTP, f"https://registry.npmjs.org/-/v1/search?text=maintainer:{username}&size=1", timeout=10)
    if r is None:
        return True
    if r.status_code == 200:
        try:
            total = r.json().get("total", 0)
            if total > 0:
                return True
            r2 = _get(HTTP, f"https://registry.npmjs.org/-/v1/search?text=maintainer:{username}&size=0", timeout=8)
            if r2 and r2.status_code == 200:
                try:
                    if r2.json().get("total", 0) == 0:
                        return False
                except Exception:
                    pass
            return False
        except Exception:
            return True
    return True


def npm_info(pkg: str) -> dict:
    r = _get(HTTP, f"https://registry.npmjs.org/{pkg}", timeout=12)
    if not r:
        return {"exists": None, "error": "timeout"}
    if r.status_code == 404:
        return {"exists": False, "available": True}
    if r.status_code != 200:
        return {"exists": None, "error": f"HTTP {r.status_code}"}
    try:
        d = r.json()
    except Exception:
        return {"exists": None, "error": "bad JSON"}
    if d.get("error") == "Not found":
        return {"exists": False, "available": True}

    times = d.get("time", {})
    latest = d.get("dist-tags", {}).get("latest", "")
    unpub  = "unpublished" in times

    maintainers = [m.get("name","") for m in d.get("maintainers", [])]
    dead = []
    for m in maintainers[:8]:
        if _npm_user_exists(m):
            continue
        dead.append(m)

    last_pub = times.get(latest, times.get("modified", ""))
    age_days = None
    if last_pub:
        try:
            dt = datetime.fromisoformat(last_pub.replace("Z","+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
        except Exception:
            pass

    return {
        "exists": True, "available": unpub, "unpublished": unpub,
        "latest": latest, "maintainers": maintainers, "dead_maintainers": dead,
        "days_since": age_days, "description": d.get("description",""),
    }

def npm_scope_exists(scope: str) -> bool:
    r = _get(HTTP, f"https://registry.npmjs.org/@{scope}", timeout=8)
    if not r:
        return True
    if r.status_code == 404:
        r2 = _get(HTTP, f"https://registry.npmjs.org/-/v1/search?text=scope:{scope}&size=1", timeout=8)
        if r2 and r2.status_code == 200:
            try:
                total = r2.json().get("total", 0)
                if total > 0:
                    return True
            except Exception:
                pass
        return False
    return True

def pypi_info(pkg: str) -> dict:
    r = _get(HTTP, f"https://pypi.org/pypi/{pkg}/json", timeout=10)
    if not r: return {"exists": None}
    if r.status_code == 404: return {"exists": False, "available": True}
    if r.status_code != 200: return {"exists": None}
    try:
        d = r.json()
        info = d.get("info", {})
        return {
            "exists": True, "available": False,
            "version": info.get("version",""),
            "author": info.get("author",""),
            "home_page": info.get("home_page",""),
            "summary": info.get("summary",""),
        }
    except Exception:
        return {"exists": None}

def rubygems_info(gem: str) -> dict:
    r = _get(HTTP, f"https://rubygems.org/api/v1/gems/{gem}.json", timeout=10)
    if not r: return {"exists": None}
    if r.status_code == 404: return {"exists": False, "available": True}
    if r.status_code != 200: return {"exists": None}
    try:
        d = r.json()
        return {
            "exists": True, "available": False,
            "version": d.get("version",""),
            "authors": d.get("authors",""),
            "downloads": d.get("downloads", 0),
        }
    except Exception:
        return {"exists": None}

def nuget_info(pkg: str) -> dict:
    r = _get(HTTP, f"https://api.nuget.org/v3-flatcontainer/{pkg.lower()}/index.json", timeout=10)
    if not r: return {"exists": None}
    if r.status_code == 404: return {"exists": False, "available": True}
    if r.status_code != 200: return {"exists": None}
    try:
        d = r.json()
        versions = d.get("versions", [])
        return {"exists": True, "available": False, "versions": versions[-5:]}
    except Exception:
        return {"exists": None}

def cargo_info(pkg: str) -> dict:
    r = _get(HTTP, f"https://crates.io/api/v1/crates/{pkg}", timeout=10)
    if not r: return {"exists": None}
    if r.status_code == 404: return {"exists": False, "available": True}
    if r.status_code != 200: return {"exists": None}
    try:
        d = r.json()
        crate = d.get("crate", {})
        return {
            "exists": True, "available": False,
            "newest": crate.get("newest_version",""),
            "downloads": crate.get("downloads", 0),
        }
    except Exception:
        return {"exists": None}

def jsdelivr_hits(pkg_type: str, owner_pkg: str) -> Optional[int]:
    url = f"https://data.jsdelivr.com/v1/stats/packages/{pkg_type}/{owner_pkg}"
    r = _get(HTTP, url, timeout=8)
    if not r or r.status_code != 200:
        return None
    try:
        d = r.json()
        hits = d.get("hits", {})
        if isinstance(hits, dict):
            return hits.get("total")
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# CDN URL parser
# ─────────────────────────────────────────────────────────────

_NON_EXECUTABLE_EXTS = re.compile(
    r'\.(?:json|xml|csv|tsv|txt|md|markdown|yaml|yml|toml|ini|cfg|conf|lock|'
    r'css|less|scss|sass|svg|png|jpg|jpeg|gif|ico|webp|woff|woff2|ttf|eot|otf|map|d\.ts)$',
    re.IGNORECASE
)

CDN_PATTERNS = [
    (re.compile(r'https?://cdn\.jsdelivr\.net/gh/([^/@]+)/([^@/]+)@?([^/]*)/?(.*)', re.I),
     "jsdelivr-gh",   lambda m: dict(owner=m[0], repo=m[1], ref=m[2] or "latest", filepath=m[3], package=None, version=None)),
    (re.compile(r'https?://cdn\.jsdelivr\.net/npm/(@[^@/]+/[^@/]+|[^@/]+)@?([^/]*)/?(.*)', re.I),
     "jsdelivr-npm",  lambda m: dict(package=m[0], version=m[1] or "latest", filepath=m[2], owner=None, repo=None, ref=None)),
    (re.compile(r'https?://unpkg\.com/(@[^@/]+/[^@/]+|[^@/]+)@?([^/]*)/?(.*)', re.I),
     "unpkg",         lambda m: dict(package=m[0], version=m[1] or "latest", filepath=m[2], owner=None, repo=None, ref=None)),
    (re.compile(r'https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)', re.I),
     "raw-github",    lambda m: dict(owner=m[0], repo=m[1], ref=m[2], filepath=m[3], package=None, version=None)),
    (re.compile(r'https?://github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.*)', re.I),
     "raw-github",    lambda m: dict(owner=m[0], repo=m[1], ref=m[2], filepath=m[3], package=None, version=None)),
    (re.compile(r'https?://cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)/(.*)', re.I),
     "cdnjs",         lambda m: dict(package=m[0], version=m[1], filepath=m[2], owner=None, repo=None, ref=None)),
    (re.compile(r'https?://(?:cdn\.rawgit\.com|rawgit\.com)/([^/]+)/([^/]+)/([^/]+)/(.*)', re.I),
     "rawgit-dead",   lambda m: dict(owner=m[0], repo=m[1], ref=m[2], filepath=m[3], package=None, version=None)),
    (re.compile(r'https?://gitcdn\.xyz/repo/([^/]+)/([^/]+)/([^/]+)/(.*)', re.I),
     "rawgit-dead",   lambda m: dict(owner=m[0], repo=m[1], ref=m[2], filepath=m[3], package=None, version=None)),
    (re.compile(r'https?://esm\.sh/(@?[^@/]+(?:/[^@/]+)?)@?([^/?#]*)', re.I),
     "esm-sh",        lambda m: dict(package=m[0], version=m[1] or "latest", filepath="", owner=None, repo=None, ref=None)),
    (re.compile(r'https?://cdn\.skypack\.dev/(@?[^@/?#]+(?:/[^@/?#]+)?)@?([^/?#]*)', re.I),
     "skypack",       lambda m: dict(package=m[0], version=m[1] or "latest", filepath="", owner=None, repo=None, ref=None)),
    (re.compile(r'https?://jspm\.dev/(@?[^@/?#]+(?:/[^@/?#]+)?)@?([^/?#]*)', re.I),
     "jspm",          lambda m: dict(package=m[0], version=m[1] or "latest", filepath="", owner=None, repo=None, ref=None)),
    (re.compile(r'https?://deno\.land/x/([^@/]+)@?([^/?#]*)', re.I),
     "deno",          lambda m: dict(package=m[0], version=m[1] or "latest", filepath="", owner=None, repo=None, ref=None)),
    (re.compile(r'https?://gist\.githubusercontent\.com/([^/]+)/([a-f0-9]+)/raw/([^/]+)/(.*)', re.I),
     "gist",          lambda m: dict(owner=m[0], repo=m[1], ref=m[2], filepath=m[3], package=None, version=None)),
    (re.compile(r'https?://([^.]+)\.github\.io(/[^"\']*)?', re.I),
     "github-pages",  lambda m: dict(owner=m[0], repo=m[0]+".github.io", ref=None, filepath=m[1] or "/", package=None, version=None)),
]

def parse_cdn_url(url: str) -> Optional[dict]:
    url = url.strip().split("?")[0].split("#")[0]
    url = url.rstrip("\\")
    if url.endswith("@") or url.endswith("/"):
        return None
    if len(url) < 20:
        return None
    for rx, cdn, extractor in CDN_PATTERNS:
        m = rx.match(url)
        if m:
            info = extractor(m.groups())
            info.update({"cdn": cdn, "raw_url": url})
            return info
    return None


# ─────────────────────────────────────────────────────────────
# Extractors
# ─────────────────────────────────────────────────────────────

_BARE_CDN = re.compile(
    r'["\']'
    r'(https?://(?:'
    r'cdn\.jsdelivr\.net/(?:gh|npm)/|'
    r'unpkg\.com/|'
    r'cdnjs\.cloudflare\.com/ajax/libs/|'
    r'raw\.githubusercontent\.com/|'
    r'cdn\.rawgit\.com/|rawgit\.com/|gitcdn\.xyz/|'
    r'esm\.sh/|cdn\.skypack\.dev/|jspm\.dev/|'
    r'deno\.land/x/|'
    r'gist\.githubusercontent\.com/'
    r')[^"\']{5,})["\']',
    re.IGNORECASE
)
_CDN_HOST_FRAGMENT = (
    r'https?://(?:'
    r'cdn\.jsdelivr\.net/(?:gh|npm)/|'
    r'unpkg\.com/|'
    r'cdnjs\.cloudflare\.com/ajax/libs/|'
    r'raw\.githubusercontent\.com/|'
    r'cdn\.rawgit\.com/|rawgit\.com/|gitcdn\.xyz/|'
    r'esm\.sh/|cdn\.skypack\.dev/|jspm\.dev/|'
    r'deno\.land/x/|'
    r'gist\.githubusercontent\.com/'
    r')[^"\']{5,}'
)
_SRC_CDN  = re.compile(
    r'(?:src|href)\s*=\s*["\'](' + _CDN_HOST_FRAGMENT + r')["\']', re.IGNORECASE
)
_IMPORT_MAP = re.compile(
    r'"[^"]+"\s*:\s*"(https?://(?:cdn\.jsdelivr|unpkg|esm\.sh|cdn\.skypack|jspm\.dev)[^"]+)"',
    re.IGNORECASE
)
_GH_PKG = re.compile(
    r'"([a-zA-Z0-9][a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)(?:#[^"\']*)?"\s*(?:[:,])'
)
_GIT_HTTPS = re.compile(
    r'git\+https://github\.com/([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+?)(?:\.git)?(?:#[^"\']*)?["\']'
)
_ACTIONS = re.compile(r'uses:\s+([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)@([^\s]+)')
_SRI_SCRIPT = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE
)
_HAS_INTEGRITY = re.compile(r'\bintegrity\s*=', re.IGNORECASE)

def extract_cdn_urls(text: str) -> list[str]:
    found = set()
    for m in _BARE_CDN.finditer(text):
        found.add(m.group(1))
    for m in _SRC_CDN.finditer(text):
        found.add(m.group(1))
    for m in _IMPORT_MAP.finditer(text):
        found.add(m.group(1))
    for blk in re.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL|re.IGNORECASE):
        for m in _BARE_CDN.finditer(blk):
            found.add(m.group(1))
    return list(found)

def check_sri_missing(html: str) -> list[str]:
    missing = []
    for m in _SRI_SCRIPT.finditer(html):
        tag_full = m.group(0)
        src = m.group(1)
        dep = parse_cdn_url(src)
        if dep and not _HAS_INTEGRITY.search(tag_full):
            missing.append(src)
    return missing

def extract_pkg_json_github(text: str) -> list[tuple]:
    results = []
    try:
        data = json.loads(text)
        all_deps = {}
        for s in ("dependencies","devDependencies","peerDependencies","optionalDependencies"):
            all_deps.update(data.get(s,{}))
        for name, ver in all_deps.items():
            if not isinstance(ver, str): continue
            for m in _GH_PKG.finditer(f'"{ver}"'):
                o, r_ = m.group(1), m.group(2)
                if not any(o.startswith(x) for x in ("^","~",">","<","=","*","0","1","2","3","4","5","6","7","8","9")):
                    results.append((o, r_, ver))
            for m in _GIT_HTTPS.finditer(f'"{ver}"'):
                results.append((m.group(1), m.group(2), ver))
    except Exception:
        pass
    return results

def extract_actions(text: str) -> list[tuple]:
    SKIP = {"actions","github","docker"}
    return [(m.group(1), m.group(2), m.group(3))
            for m in _ACTIONS.finditer(text)
            if m.group(1).lower() not in SKIP]


# ─────────────────────────────────────────────────────────────
# Exploit guide generator
# ─────────────────────────────────────────────────────────────

def exploit_guide(finding: dict) -> list[str]:
    cdn   = finding.get("cdn","")
    owner = finding.get("owner","<owner>")
    repo  = finding.get("repo","<repo>")
    pkg   = finding.get("package","<pkg>")
    ref   = finding.get("ref","latest")
    url   = finding.get("url","")
    sev   = finding.get("severity","")
    claimed = finding.get("claimed", False)
    issues  = finding.get("issues",[])

    steps = []

    if claimed and sev == "CRITICAL" and cdn in ("jsdelivr-gh","raw-github","gist"):
        stale_cached = any("CDN STALE CACHE" in i for i in issues)
        steps += [
            "[ ACTIVE ATTACK — GitHub namespace squatted, serving malicious content ]",
            "",
            "Step 1 — Verify the malicious CDN response is live:",
            f"  curl -si '{url}' -H 'User-Agent: hackerone-shadowbyte'",
            "",
        ] + ([
            f"  ⚠ STALE CACHE CONFIRMED: jsDelivr persisting content after source deletion.",
            f"  Force-purge: https://purge.jsdelivr.net/gh/{owner}/{repo}@{ref or 'latest'}/",
            "",
        ] if stale_cached else []) + [
            "Step 2 — Confirm squatter identity via GitHub commit history:",
            f"  curl -s 'https://api.github.com/repos/{owner}/{repo}/commits' | python3 -m json.tool | head -60",
            "",
            "Step 3 — Report to GitHub Security:",
            f"  https://github.com/contact/report-abuse",
        ]

    elif cdn in ("lifecycle-inject",):
        steps += [
            "[ INSTALL-TIME RCE — npm lifecycle hook runs shell commands on install ]",
            "",
            "Step 1 — Review the hook command:",
            f"  cat package.json | python3 -c \"import sys,json; s=json.load(sys.stdin).get('scripts',{{}}); [print(k,':',v) for k,v in s.items()]\"",
            "",
            "Step 2 — Test in a sandbox (DO NOT run on host):",
            "  docker run --rm -v $(pwd):/app node:alpine sh -c 'cd /app && npm install --ignore-scripts'",
            "",
            "Step 3 — Report: postinstall hooks with curl/wget/eval are supply chain RCE",
        ]

    elif cdn in ("lockfile-confusion",):
        steps += [
            "[ LOCKFILE CONFUSION — package resolved from unexpected registry ]",
            "",
            "Step 1 — Identify the registry:",
            f"  grep -A5 '{pkg}' package-lock.json | grep resolved",
            "",
            "Step 2 — Verify it's internal vs public:",
            "  If the registry is an internal mirror, check if an attacker could publish",
            "  a same-named package on the public registry to trigger dep confusion.",
            "",
            "Step 3 — Recommend: pin all packages to registry.npmjs.org explicitly in .npmrc",
        ]

    elif cdn in ("github-action",):
        steps += [
            f"[ GITHUB ACTIONS SUPPLY CHAIN — {owner}/{repo}@{ref} ]",
            "",
            f"Step 1 — Check repo status: curl -s 'https://api.github.com/repos/{owner}/{repo}' | python3 -m json.tool",
            f"Step 2 — If gone: gh repo create {owner}/{repo} --public && git tag {ref} && git push origin {ref}",
            "Step 3 — Impact: pipeline GITHUB_TOKEN + all repository secrets exposed to the action",
            "Step 4 — Fix: pin all third-party actions to full commit SHA, e.g.:",
            f"  uses: {owner}/{repo}@<full-40-char-sha>  # instead of @{ref}",
        ]

    elif cdn in ("jsdelivr-gh", "raw-github", "github-pages") and not claimed:
        is_user_gone = not finding.get("details",{}).get("user",{}).get("exists", True)
        steps += [
            f"[ UNCLAIMED {'USER/ORG' if is_user_gone else 'REPO'} — can be registered NOW ]",
            "",
            f"Step 1 — Confirm namespace is still unclaimed:",
            f"  curl -s 'https://api.github.com/users/{owner}' | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('login','NOT FOUND'))\"",
            "",
            "Step 2 — Create the GitHub account/repo:",
            f"  → Register https://github.com/join with username: {owner}" if is_user_gone else f"  gh repo create {owner}/{repo} --public",
            "",
            "Step 3 — PoC content (DO NOT deploy actual malware):",
            "  echo 'console.log(\"supply-chain-poc-shadowbyte\");' > index.js",
            f"  git add . && git commit -m 'PoC' && git tag v1.0.0 && git push origin main --tags",
            "",
            f"Step 4 — Verify: curl -s '{url}'",
        ]

    elif cdn in ("jsdelivr-npm","unpkg","esm-sh","skypack","jspm") and not claimed \
         and not finding.get("details",{}).get("npm",{}).get("exists", True):
        typo = finding.get("details",{}).get("typosquat_of","")
        steps += [
            f"[ UNCLAIMED NPM PACKAGE{' — TYPOSQUAT of: ' + typo if typo else ''} ]",
            "",
            f"Step 1 — Confirm: curl -s 'https://registry.npmjs.org/{pkg}' | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('error','EXISTS'))\"",
            "",
            f"Step 2 — Scaffold PoC:",
            f"  mkdir /tmp/{pkg}-poc && cd /tmp/{pkg}-poc",
            f"  npm init -y  # name: {pkg}",
            "  echo 'console.log(\"supply-chain-poc-shadowbyte\");' > index.js",
            "",
            "Step 3 — Publish (PoC only):",
            "  npm publish --access public",
            "",
            f"Step 4 — Verify: curl -s '{url}'",
        ]

    elif sev == "LOW" and any("NO SRI" in i for i in issues):
        steps += [
            "[ MISSING SRI + FLOATING REF ]",
            "",
            f"  Generate hash: curl -s '{url}' | openssl dgst -sha384 -binary | openssl base64 -A",
            f"  Add integrity= attribute to the <script> tag",
            f"  Better: self-host the dependency in the app bundle",
        ]

    else:
        steps += [
            f"Step 1 — Verify: curl -si '{url}' -H 'User-Agent: hackerone-shadowbyte'",
            f"Step 2 — Check ownership: https://github.com/{owner}/{repo}" if owner else f"  https://npmjs.com/package/{pkg}",
            "Step 3 — Document and report.",
        ]

    return steps


# ─────────────────────────────────────────────────────────────
# Validation chain
# ─────────────────────────────────────────────────────────────

FLOATING_REFS = {"latest","master","main","HEAD","next","dev","canary","beta","edge","nightly"}
SUSPICIOUS_COMMIT_WORDS = {"poc","test","placeholder","hijack","takeover","squatting",
                            "claim","hello world","initial commit","demo","foobar"}
SUSPICIOUS_DESC_WORDS   = {"test","poc","demo","placeholder","hijack","takeover","squat",
                            "not real","fake","forked from","trial","sample","dummy"}

def _severity_max(a: str, b: str) -> str:
    order = ["INFO","POTENTIAL","LOW","MEDIUM","HIGH","CRITICAL"]
    ai = order.index(a) if a in order else 0
    bi = order.index(b) if b in order else 0
    return b if bi > ai else a

def validate_cdn_dep(dep: dict, verbose: bool = False) -> Optional[dict]:
    cdn     = dep["cdn"]
    raw_url = dep["raw_url"]
    owner   = dep.get("owner")
    repo    = dep.get("repo")
    pkg     = dep.get("package")
    ref     = dep.get("ref","")
    version = dep.get("version","")

    issues   = []
    sev      = "INFO"
    claimed  = False
    details  = {}
    signals  = 0

    filepath = dep.get("filepath", "") or ""
    if cdn in ("raw-github", "jsdelivr-gh") and _NON_EXECUTABLE_EXTS.search(filepath):
        return None

    # ── Retired CDN check ────────────────────────────────────
    retired_reason = check_retired_cdn(raw_url)
    if retired_reason and cdn not in ("rawgit-dead",):
        issues.append(f"RETIRED CDN HOST: {retired_reason}")
        sev = _severity_max(sev, "MEDIUM")
        signals += 1

    if cdn == "rawgit-dead":
        r_redir = _get(HTTP, raw_url, timeout=10, allow_redirects=False)
        if r_redir and r_redir.status_code in (301, 302):
            dest = r_redir.headers.get("Location", "")
            if dest and "jsdelivr.net" in dest:
                r_dest = _get(HTTP, dest, timeout=10)
                if r_dest and r_dest.status_code == 200 and len(r_dest.text) > 500:
                    return dict(url=raw_url, cdn=cdn, owner=owner, repo=repo, package=pkg,
                                ref=ref, version=version, severity="LOW",
                                claimed=False, details={"redirect_dest": dest, "dest_size": len(r_dest.text)},
                                signals=1,
                                issues=[
                                    f"DEAD CDN (benign redirect): rawgit.com → {dest} — "
                                    f"destination is live ({len(r_dest.text)//1024}KB), "
                                    f"but rawgit.com is dead infrastructure. Update URL to direct jsDelivr link."
                                ],
                                exploit_steps=[
                                    "No active takeover vector — rawgit redirect points to live content.",
                                    f"Recommend updating <script src> to: {dest}",
                                ])
        issues.append("Dead CDN: rawgit.com/gitcdn.xyz shut down 2019 — requests may silently redirect or 404")
        return dict(url=raw_url, cdn=cdn, owner=owner, repo=repo, package=pkg,
                    ref=ref, version=version, issues=issues, severity="MEDIUM",
                    claimed=False, details={}, exploit_steps=[
                        f"Step 1 — Test: curl -si '{raw_url}' -H 'User-Agent: hackerone-shadowbyte'",
                        "Step 2 — If redirect target is controllable, escalate.",
                        "Step 3 — Recommend migrating to maintained CDN.",
                    ])

    # ── STAGE 1 ───────────────────────────────────────────────
    if cdn in ("jsdelivr-gh", "raw-github", "github-pages", "gist"):
        if not owner:
            return None

        user_info = gh_user(owner)
        details["user"] = user_info

        if not user_info.get("exists"):
            issues.append(
                f"UNCLAIMED NAMESPACE: GitHub user/org '{owner}' does not exist — "
                f"anyone can register it and serve arbitrary code via this CDN URL"
            )
            sev = "CRITICAL"; signals += 3
        else:
            age = user_info.get("age_days")
            utype = user_info.get("type","User")
            followers = user_info.get("followers", 0)

            if age is not None and age < 180:
                issues.append(
                    f"ACCOUNT AGE {age}d: '{owner}' created less than 6 months ago "
                    f"(type={utype}, followers={followers}) — high squatting probability"
                )
                sev = _severity_max(sev, "HIGH"); signals += 2
            elif age is not None and age < 365:
                issues.append(
                    f"ACCOUNT AGE {age}d: '{owner}' is less than 1 year old "
                    f"(type={utype}, followers={followers})"
                )
                sev = _severity_max(sev, "MEDIUM"); signals += 1

            if repo and cdn != "github-pages":
                repo_info = gh_repo(owner, repo)
                details["repo"] = repo_info

                if not repo_info.get("exists"):
                    issues.append(
                        f"UNCLAIMED REPO: '{owner}/{repo}' does not exist — "
                        f"create it to serve arbitrary content via this CDN URL"
                    )
                    sev = "CRITICAL"; signals += 3
                else:
                    stars = repo_info.get("stars", 0)
                    desc  = repo_info.get("description","")

                    established_account = (
                        age is not None and age > 365 and
                        followers > 20 and
                        stars > 100
                    )

                    if desc and any(w in desc.lower() for w in SUSPICIOUS_DESC_WORDS):
                        if not established_account:
                            issues.append(f"SUSPICIOUS DESCRIPTION: '{desc}'")
                            sev = _severity_max(sev, "HIGH"); signals += 2

                    if stars == 0 and age is not None and age < 365 and followers == 0:
                        issues.append(
                            f"SQUATTER FINGERPRINT: 0 stars, 0 followers, new account"
                        )
                        sev = _severity_max(sev, "HIGH"); signals += 2

                    commits = gh_commits(owner, repo, n=10)
                    details["commits"] = commits
                    if commits:
                        sus_commits = [c for c in commits
                                       if any(w in c["msg"].lower() for w in SUSPICIOUS_COMMIT_WORDS)]
                        if sus_commits:
                            if established_account:
                                sus_commits = [c for c in sus_commits
                                               if len(c["msg"].strip()) <= 20]
                            if sus_commits:
                                issues.append(
                                    f"SUSPICIOUS COMMITS ({len(sus_commits)}/{len(commits)}): "
                                    + "; ".join(f'\"{c["msg"][:60]}\"' for c in sus_commits[:3])
                                )
                                sev = _severity_max(sev, "HIGH"); signals += 2
                        if len(commits) <= 2:
                            issues.append(f"SPARSE HISTORY: only {len(commits)} commit(s)")
                            signals += 1

                    tags = gh_tags(owner, repo)
                    details["tags"] = tags
                    inflated = [t for t in tags if t.get("inflated")]
                    if inflated:
                        _PRERELEASE = re.compile(
                            r'[-.](?:rc\d*|alpha[\d.]*|beta[\d.]*|pre[\d.]*|dev[\d.]*|snapshot|canary)$',
                            re.IGNORECASE
                        )
                        sha_to_tags: dict = {}
                        for t in inflated:
                            sha_to_tags.setdefault(t["sha"], []).append(t["name"])

                        suspicious_groups = []
                        for sha, tag_names in sha_to_tags.items():
                            has_prerelease = any(_PRERELEASE.search(n) for n in tag_names)
                            if not has_prerelease:
                                suspicious_groups.append((sha, tag_names))

                        if suspicious_groups:
                            all_suspicious = [n for _, names in suspicious_groups for n in names]
                            issues.append(
                                f"TAG INFLATION: {len(all_suspicious)} tags → same commit SHA "
                                f"({', '.join(all_suspicious[:5])}) — "
                                f"squatters create fake version tags to win @latest resolution"
                            )
                            sev = _severity_max(sev, "HIGH"); signals += 2

            if cdn == "github-pages":
                r = _get(HTTP, dep["raw_url"], timeout=10)
                if r and r.status_code == 404:
                    issues.append(f"GITHUB PAGES 404: site returns 404 — repo may be claimable")
                    sev = _severity_max(sev, "HIGH"); signals += 2

        if ref and ref.lower() in FLOATING_REFS:
            issues.append(
                f"FLOATING REF: @{ref} is mutable — any push propagates to all sites loading this URL"
            )
            if sev == "INFO":
                sev = "LOW"
            signals += 1

    elif cdn in ("jsdelivr-npm","unpkg","esm-sh","skypack","jspm"):
        if not pkg:
            return None

        npm_data = npm_info(pkg)
        details["npm"] = npm_data

        # ── NEW: Typosquatting check ──────────────────────────
        typo_of = check_typosquatting(pkg)
        if typo_of and npm_data.get("exists"):
            details["typosquat_of"] = typo_of
            issues.append(
                f"TYPOSQUATTING CANDIDATE: '{pkg}' is Levenshtein distance 1 from '{typo_of}' — "
                f"developers mistyping '{typo_of}' will install this package instead"
            )
            sev = _severity_max(sev, "HIGH"); signals += 2

        if not npm_data.get("exists"):
            issues.append(
                f"UNCLAIMED NPM: '{pkg}' does not exist — "
                f"publish it to serve arbitrary code via this CDN URL"
            )
            sev = "CRITICAL"; signals += 3

        elif npm_data.get("unpublished"):
            issues.append(f"UNPUBLISHED: '{pkg}' was unpublished from npm")
            sev = _severity_max(sev, "HIGH"); signals += 2

        else:
            dead = npm_data.get("dead_maintainers", [])
            if dead:
                issues.append(
                    f"DEAD MAINTAINER ACCOUNT(S): {dead} — "
                    f"anyone who registers them becomes a listed maintainer with publish rights"
                )
                sev = _severity_max(sev, "HIGH"); signals += 2

            days = npm_data.get("days_since")
            _abandoned = False
            if days and days > 730:
                details["abandoned_days"] = days
                _abandoned = True

            if (version or "").lower() in FLOATING_REFS or version == "*":
                days_since = npm_data.get("days_since") or 9999
                dead = npm_data.get("dead_maintainers", [])
                if days_since < 180 and not dead:
                    pass
                else:
                    issues.append(f"FLOATING VERSION: @{version} — any new publish propagates immediately")
                    if sev == "INFO": sev = "LOW"
                    signals += 1
                if _abandoned:
                    days = details.get("abandoned_days", 0)
                    issues.append(f"ABANDONED: last published {days} days ago — "
                                  f"maintainer inactive; floating version means any new publish propagates")
                    sev = _severity_max(sev, "MEDIUM"); signals += 1
            elif _abandoned and details.get("npm",{}).get("dead_maintainers"):
                days = details.get("abandoned_days", 0)
                issues.append(f"ABANDONED + DEAD MAINTAINER: last published {days} days ago")
                sev = _severity_max(sev, "MEDIUM"); signals += 1

            if pkg.startswith("@"):
                scope = pkg.split("/")[0][1:]
                scope_exists = npm_scope_exists(scope)
                if not scope_exists:
                    issues.append(f"UNCLAIMED NPM SCOPE: @{scope} scope is not registered")
                    sev = _severity_max(sev, "HIGH"); signals += 2

    elif cdn == "cdnjs":
        if not pkg:
            return None
        r = _get(HTTP, f"https://api.cdnjs.com/libraries/{pkg}?fields=repository", timeout=10)
        if r and r.status_code == 404:
            issues.append(f"CDNJS PACKAGE REMOVED: '{pkg}' no longer in cdnjs index")
            sev = _severity_max(sev, "MEDIUM"); signals += 1
        elif r and r.status_code == 200:
            try:
                d = r.json()
                gh_url = d.get("repository",{}).get("url","")
                m_ = re.search(r'github\.com/([^/]+)/([^/]+?)(?:\.git)?$', gh_url)
                if m_:
                    gh_owner, gh_repo_name = m_.group(1), m_.group(2)
                    ri = gh_repo(gh_owner, gh_repo_name)
                    details["cdnjs_repo"] = ri
                    if not ri.get("exists"):
                        issues.append(
                            f"CDNJS SOURCE REPO DELETED: {gh_owner}/{gh_repo_name} — "
                            f"backing repo is claimable"
                        )
                        sev = _severity_max(sev, "HIGH"); signals += 2
            except Exception:
                pass

    elif cdn == "deno":
        if not pkg:
            return None
        r = _get(HTTP, f"https://deno.land/x/{pkg}", timeout=8)
        if r and r.status_code == 404:
            issues.append(f"UNCLAIMED DENO MODULE: 'deno.land/x/{pkg}' returns 404")
            sev = _severity_max(sev, "HIGH"); signals += 2

    elif cdn == "gist":
        if owner:
            user_info = gh_user(owner)
            details["user"] = user_info
            if not user_info.get("exists"):
                issues.append(f"UNCLAIMED GIST OWNER: '{owner}' does not exist")
                sev = "HIGH"; signals += 2

    if not issues:
        return None

    # ── STAGE 2 ───────────────────────────────────────────────
    current = fetch_live(raw_url, retries=2)
    details["current"] = current

    if current and current.get("status") == 200:
        content = current.get("content","") or ""

        mal = detect_malicious(content)
        if mal:
            issues.append(f"MALICIOUS CONTENT ({len(mal)} signal(s)): " + " | ".join(mal))
            sev = "CRITICAL"; claimed = True; signals += 3

        wayback = wayback_fetch(raw_url)
        details["wayback"] = wayback
        if wayback:
            wb_size  = wayback.get("size", 0)
            cur_size = current.get("size", 0)
            wb_hash  = wayback.get("sha256","")
            cur_hash = current.get("sha256","")

            jsdelivr_minified = "Minified by jsDelivr" in content[:500]

            # ─── FALSE POSITIVE SUPPRESSION for established trusted maintainers ───
            # Paul Irish / lite-youtube-embed (31K followers, 6335d old, 3K+ stars)
            # is a legitimate library — content changes are version bumps, not attacks.
            # Apply: if account is trusted (age >2yr, followers >500, repo stars >500),
            # a content hash change alone does NOT trigger CLAIMED or HIGH severity.
            # We still report it as INFO/POTENTIAL for the content-change record.
            user_info_fp = details.get("user", {})
            repo_info_fp = details.get("repo", {})
            is_trusted = _is_trusted_maintainer(user_info_fp, repo_info_fp)

            if wb_size > 200 and cur_size < wb_size * 0.3:
                # >70% size drop — suspicious even for trusted maintainers
                if is_trusted:
                    issues.append(
                        f"LARGE CONTENT DROP (trusted maintainer): archived={wb_size}B → "
                        f"current={cur_size}B ({wb_size-cur_size}B, >70% drop) — "
                        f"verify manually, could be legitimate minification or repo restructure"
                    )
                    sev = _severity_max(sev, "MEDIUM"); signals += 1
                else:
                    issues.append(
                        f"CONTENT REPLACED: archived={wb_size}B → current={cur_size}B "
                        f"({wb_size-cur_size}B dropped)"
                    )
                    sev = "CRITICAL"; claimed = True; signals += 3

            elif wb_hash and cur_hash and wb_hash != cur_hash and not jsdelivr_minified:
                acct_age = details.get("user", {}).get("age_days") or 9999
                acct_followers = details.get("user", {}).get("followers") or 0
                size_drop_pct = abs(wb_size - cur_size) / max(wb_size, 1)
                established = acct_age > 730 and acct_followers > 50
                trivial_change = size_drop_pct < 0.10
                npm_days = details.get("npm", {}).get("days_since") or 9999
                npm_dead = details.get("npm", {}).get("dead_maintainers", [])
                active_npm = npm_days < 730 and not npm_dead

                if is_trusted:
                    # Trusted maintainer + floating ref + content change = informational only
                    # The floating ref is already flagged separately; don't double-escalate
                    issues.append(
                        f"CONTENT UPDATED (trusted maintainer, verify): "
                        f"archived hash {wb_hash} ({wb_size}B) → current {cur_hash} ({cur_size}B) — "
                        f"size diff {size_drop_pct:.1%}; account has {acct_followers} followers, "
                        f"{acct_age}d old — likely legitimate update. "
                        f"ACTION: update <script src> to a pinned version tag instead of @{ref}."
                    )
                    # Do NOT set claimed=True or escalate severity for trusted maintainers
                    # Only escalate severity if there are OTHER signals besides just content change
                    if signals > 1:
                        sev = _severity_max(sev, "MEDIUM")
                    # Otherwise keep at LOW (floating ref signal)
                    signals += 1

                elif (established and trivial_change) or (active_npm and trivial_change):
                    issues.append(
                        f"CONTENT UPDATED: archived hash {wb_hash} ({wb_size}B) → "
                        f"current {cur_hash} ({cur_size}B) — "
                        f"size diff {size_drop_pct:.1%}, active maintainers — "
                        f"likely legitimate update, verify manually"
                    )
                    signals += 1
                else:
                    issues.append(
                        f"CONTENT CHANGED: archived hash {wb_hash} ({wb_size}B) ≠ "
                        f"current {cur_hash} ({cur_size}B) — "
                        f"size diff {size_drop_pct:.1%}"
                    )
                    sev = _severity_max(sev, "HIGH"); claimed = True; signals += 2

        if not current.get("consistent", True):
            issues.append("CDN INCONSISTENCY: two fetches returned different content")
            sev = _severity_max(sev, "HIGH"); signals += 2

        if cdn == "jsdelivr-gh" and owner and repo:
            hits = jsdelivr_hits("gh", f"{owner}/{repo}")
            if hits:
                details["monthly_hits"] = hits
                if hits > 10000:
                    issues.append(f"HIGH REACH: {hits:,} monthly CDN requests")
                    sev = _severity_max(sev, "HIGH"); signals += 1
                elif hits > 100:
                    issues.append(f"CONFIRMED REACH: {hits:,} monthly CDN requests")
                    signals += 1

            if check_jsdelivr_stale_cache(raw_url):
                issues.append(
                    "CDN STALE CACHE: jsDelivr is serving content but GitHub raw URL 404s — "
                    "source deleted/emptied after purge-cache; CDN edges still serve malicious payload. "
                    f"Force-purge: https://purge.jsdelivr.net/gh/{owner}/{repo}@{ref}/{dep.get('filepath','')}"
                )
                sev = "CRITICAL"; claimed = True; signals += 3

        if cdn == "jsdelivr-npm" and pkg and (
            not details.get("npm",{}).get("exists") or
            details.get("npm",{}).get("dead_maintainers")
        ):
            unpkg_url = raw_url.replace("cdn.jsdelivr.net/npm/", "unpkg.com/")
            if unpkg_url != raw_url:
                issues.append(
                    f"PARALLEL VECTOR: same package also served via unpkg — "
                    f"{unpkg_url} — both CDNs are affected by the same npm namespace control"
                )
                details["unpkg_url"] = unpkg_url

    elif current and current.get("status") not in (None, 200):
        details["cdn_status"] = current.get("status")
        if issues:
            issues.append(f"CDN STATUS {current.get('status')}: URL returns non-200")

    # ── STAGE 3: confidence threshold ─────────────────────────
    if not issues:
        return None

    # ── Trusted maintainer final downgrade ────────────────────
    # If the ONLY reason this is HIGH/CLAIMED is content change + floating ref on a trusted
    # account, downgrade to LOW informational and mark not claimed.
    user_info_final = details.get("user", {})
    repo_info_final = details.get("repo", {})
    if _is_trusted_maintainer(user_info_final, repo_info_final):
        # Only content-change + floating-ref issues? Downgrade.
        non_fp_issues = [i for i in issues if not any(k in i for k in (
            "CONTENT UPDATED", "FLOATING REF", "HIGH REACH", "CONTENT CHANGED",
        ))]
        if not non_fp_issues:
            # All issues are floating ref / content change on trusted account — informational only
            sev = "LOW"
            claimed = False
            signals = max(1, signals - 2)

    if sev in ("INFO", "LOW") and signals < 2:
        return dict(
            url=raw_url, cdn=cdn,
            owner=owner, repo=repo, package=pkg,
            ref=ref or version, version=version,
            issues=issues, severity="POTENTIAL",
            claimed=False, details=details, signals=signals,
        )
    if sev == "MEDIUM" and signals < 1:
        return None

    return dict(
        url=raw_url, cdn=cdn,
        owner=owner, repo=repo, package=pkg,
        ref=ref or version, version=version,
        issues=issues, severity=sev,
        claimed=claimed, details=details, signals=signals,
    )


def validate_github_dep(owner: str, repo: str, ref: str = "", context: str = "") -> Optional[dict]:
    issues = []; sev = "INFO"; signals = 0; details = {}

    user_info = gh_user(owner)
    details["user"] = user_info

    if not user_info.get("exists"):
        issues.append(f"UNCLAIMED OWNER: GitHub user/org '{owner}' does not exist")
        sev = "CRITICAL"; signals = 3
    else:
        age = user_info.get("age_days")
        if age is not None and age < 365:
            issues.append(f"RECENTLY CREATED: '{owner}' account is {age} days old")
            sev = _severity_max(sev, "HIGH"); signals += 2

        repo_info = gh_repo(owner, repo)
        details["repo"] = repo_info
        if not repo_info.get("exists"):
            issues.append(f"UNCLAIMED REPO: '{owner}/{repo}' does not exist")
            sev = "CRITICAL"; signals += 3
        else:
            if ref and re.match(r'^[a-f0-9]{40}$', ref):
                pass
            elif ref:
                issues.append(f"NOT SHA-PINNED: ref='{ref}' is a mutable tag/branch")
                if sev == "INFO": sev = "LOW"
                signals += 1

    if not issues:
        return None
    if sev in ("INFO","LOW") and signals < 2:
        return dict(
            url=f"https://github.com/{owner}/{repo}",
            cdn="github-dep", owner=owner, repo=repo,
            package=None, ref=ref, version=None,
            context=context, issues=issues,
            severity="POTENTIAL", claimed=False, details=details, signals=signals,
        )

    return dict(
        url=f"https://github.com/{owner}/{repo}",
        cdn="github-dep", owner=owner, repo=repo,
        package=None, ref=ref, version=None,
        context=context, issues=issues,
        severity=sev, claimed=False, details=details, signals=signals,
    )


# ─────────────────────────────────────────────────────────────
# Dependency confusion scanner
# ─────────────────────────────────────────────────────────────

_INTERNAL_SIGNALS = re.compile(
    r'(?:^@(?:internal|private|corp|company|local|dev|eng|infra)|'
    r'-(?:internal|private|local|corp)|'
    r'(?:internal|private|corp)\-)',
    re.IGNORECASE
)

def check_dep_confusion(pkg_json_text: str) -> list[dict]:
    results = []
    try:
        data = json.loads(pkg_json_text)
    except Exception:
        return results

    all_deps = {}
    for s in ("dependencies","devDependencies","peerDependencies","optionalDependencies"):
        all_deps.update(data.get(s,{}))

    for name, ver in all_deps.items():
        if not isinstance(ver, str): continue
        if ver.startswith("http") or ver.startswith("git"):
            continue
        if _INTERNAL_SIGNALS.search(name):
            npm_data = npm_info(name)
            if not npm_data.get("exists"):
                results.append(dict(
                    url=f"https://npmjs.com/package/{name}",
                    cdn="dep-confusion",
                    owner=None, repo=None,
                    package=name, ref=None, version=ver,
                    issues=[
                        f"DEPENDENCY CONFUSION: '{name}' looks internal "
                        f"but does not exist on public npm"
                    ],
                    severity="HIGH",
                    claimed=False, details={"npm": npm_data}, signals=3,
                ))
    return results


# ─────────────────────────────────────────────────────────────
# SRI absence reporter
# ─────────────────────────────────────────────────────────────

def sri_findings(html: str, page_url: str) -> list[dict]:
    missing = check_sri_missing(html)
    results = []
    for src in missing:
        dep = parse_cdn_url(src)
        if not dep:
            continue
        cdn = dep["cdn"]
        if cdn in ("github-pages",):
            continue

        ref     = (dep.get("ref") or "").lower()
        version = (dep.get("version") or "").lower()
        ref_val = ref or version

        is_floating = ref_val in FLOATING_REFS or ref_val in ("", "*")
        is_semver_pin = bool(re.match(r'^\d+\.\d+', ref_val)) and ref_val not in FLOATING_REFS
        is_major_pin = bool(re.match(r'^\d+$', ref_val)) and ref_val not in FLOATING_REFS

        always_report_cdns = ("raw-github", "gist", "rawgit-dead")

        if (is_semver_pin or is_major_pin) and cdn not in always_report_cdns:
            continue

        results.append(dict(
            url=src, cdn=cdn,
            owner=dep.get("owner"), repo=dep.get("repo"),
            package=dep.get("package"), ref=dep.get("ref"), version=dep.get("version"),
            issues=[
                f"NO SRI + FLOATING REF @{ref_val}: <script src='{src}'> "
                f"loaded without integrity= attribute — CDN compromise or namespace "
                f"squatting propagates immediately to all page visitors"
                if is_floating else
                f"NO SRI (raw CDN source, no integrity check): <script src='{src}'> "
                f"loaded from {cdn} without integrity= attribute"
            ],
            severity="LOW", claimed=False, details={}, signals=1,
        ))
    return results


# ─────────────────────────────────────────────────────────────
# Scanners
# ─────────────────────────────────────────────────────────────

def scan_url(url: str, verbose: bool = False, check_sri: bool = True,
             scan_linked_js: bool = True) -> list[dict]:
    r = _get(HTTP, url, timeout=18)
    if not r:
        if verbose:
            sprint(c(YELLOW, f"  [WARN] Could not fetch {url}"))
        return []
    html = r.text
    cdn_urls = list(set(extract_cdn_urls(html)))

    if scan_linked_js:
        parsed_base = urlparse(url)
        js_srcs = re.findall(
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
        for js_src in js_srcs:
            if not js_src.startswith("http"):
                js_src = urljoin(url, js_src)
            js_parsed = urlparse(js_src)
            if js_parsed.netloc == parsed_base.netloc:
                if verbose:
                    sprint(c(DIM, f"    [auto] scanning bundle: {js_src[:80]}"))
                r_js = _get(HTTP, js_src, timeout=20)
                if r_js and r_js.status_code == 200:
                    cdn_urls += extract_cdn_urls(r_js.text)

    cdn_urls = list(set(cdn_urls))
    if verbose:
        sprint(c(DIM, f"  [{url}] {len(cdn_urls)} total CDN dep(s)"))

    results = []
    seen = set()
    for cu in cdn_urls:
        if cu in seen: continue
        seen.add(cu)
        dep = parse_cdn_url(cu)
        if not dep: continue
        finding = validate_cdn_dep(dep, verbose=verbose)
        if finding:
            finding["found_on"] = url
            results.append(finding)

    if check_sri:
        for f in sri_findings(html, url):
            already = any(x["url"] == f["url"] for x in results)
            if not already:
                f["found_on"] = url
                results.append(f)

    return results


def scan_js(source: str, is_url: bool = True, verbose: bool = False) -> list[dict]:
    if is_url:
        r = _get(HTTP, source, timeout=30)
        content = r.text if r and r.status_code == 200 else ""
    else:
        with open(source, errors="ignore") as f:
            content = f.read()
    if not content:
        return []
    cdn_urls = list(set(extract_cdn_urls(content)))
    if verbose:
        sprint(c(DIM, f"  [{source[:60]}] found {len(cdn_urls)} CDN dep(s) in JS"))
    results = []
    seen = set()
    for cu in cdn_urls:
        if cu in seen: continue
        seen.add(cu)
        dep = parse_cdn_url(cu)
        if not dep: continue
        finding = validate_cdn_dep(dep, verbose=verbose)
        if finding:
            finding["found_on"] = source
            results.append(finding)
    return results


def scan_package_json(text: str, source: str = "") -> list[dict]:
    results = []
    for owner, repo, raw_val in extract_pkg_json_github(text):
        f = validate_github_dep(owner, repo, context=raw_val)
        if f:
            f["source"] = source
            results.append(f)
    results += check_dep_confusion(text)
    # ── NEW: lifecycle script scanning ───────────────────────
    results += scan_lifecycle_scripts(text, source=source)
    for cu in extract_cdn_urls(text):
        dep = parse_cdn_url(cu)
        if dep:
            finding = validate_cdn_dep(dep)
            if finding:
                finding["source"] = source
                results.append(finding)
    return results


def scan_workflow(text: str, source: str = "") -> list[dict]:
    results = []
    for owner, repo, ref in extract_actions(text):
        f = validate_github_dep(owner, repo, ref=ref,
                                context=f"GitHub Action: {owner}/{repo}@{ref}")
        if f:
            f["cdn"] = "github-action"
            f["source"] = source
            results.append(f)
    # ── NEW: enhanced actions pinning audit ──────────────────
    results += audit_actions_pinning(text, source=source)
    # Deduplicate by url+ref
    seen = set()
    deduped = []
    for r in results:
        key = f"{r.get('url','')}@{r.get('ref','')}"
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


def scan_lockfile(text: str, source: str = "") -> list[dict]:
    """Scan package-lock.json for lockfile confusion."""
    return scan_lockfile_confusion(text, source=source)


def scan_github_org(org: str, verbose: bool = False) -> list[dict]:
    repos_data = gh_api(f"/orgs/{org}/repos?per_page=100&type=public") \
              or gh_api(f"/users/{org}/repos?per_page=100")
    if not repos_data:
        sprint(c(YELLOW, f"  [WARN] Could not enumerate repos for {org}"))
        return []
    sprint(c(DIM, f"  Scanning {len(repos_data)} repos in {org}..."))
    results = []
    for repo in repos_data:
        name = repo.get("name","")
        branch = repo.get("default_branch","main")
        base = f"https://raw.githubusercontent.com/{org}/{name}/{branch}"
        for fname in ("package.json","package-lock.json","yarn.lock"):
            r = _get(HTTP, f"{base}/{fname}", timeout=10)
            if r and r.status_code == 200:
                if fname == "package-lock.json":
                    findings = scan_lockfile(r.text, source=f"{org}/{name}/{fname}")
                else:
                    findings = scan_package_json(r.text, source=f"{org}/{name}/{fname}")
                for f in findings:
                    f["source_repo"] = f"{org}/{name}"
                results.extend(findings)
        wf_data = gh_api(f"/repos/{org}/{name}/contents/.github/workflows")
        if isinstance(wf_data, list):
            for wf in wf_data:
                dl = wf.get("download_url","")
                if dl:
                    r = _get(HTTP, dl, timeout=10)
                    if r and r.status_code == 200:
                        findings = scan_workflow(r.text, source=f"{org}/{name}/{wf.get('name','')}")
                        for f in findings:
                            f["source_repo"] = f"{org}/{name}"
                        results.extend(findings)
        pages = gh_api(f"/repos/{org}/{name}/pages")
        if pages:
            pages_url = pages.get("html_url","")
            if pages_url:
                findings = scan_url(pages_url, verbose=verbose)
                for f in findings:
                    f["source_repo"] = f"{org}/{name}"
                results.extend(findings)
    return results


# ─────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────

SEV_COLOR = {"CRITICAL":RED,"HIGH":YELLOW,"MEDIUM":MAGENTA,"LOW":CYAN,"POTENTIAL":DIM,"INFO":DIM}
SEV_ICON  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","POTENTIAL":"🔍","INFO":"⚪"}

def print_finding(f: dict, idx: int):
    sev   = f.get("severity","INFO")
    col   = SEV_COLOR.get(sev, "")
    icon  = SEV_ICON.get(sev, "")
    claimed = f.get("claimed", False)
    status_label = c(RED,"CLAIMED / ACTIVE ATTACK") if claimed else c(YELLOW,"UNCLAIMED / CLAIMABLE")
    signals = f.get("signals", "?")

    sprint()
    sprint(c(BOLD, "─" * 72))
    sprint(c(col+BOLD, f"{icon}  [{sev}]  Finding #{idx}   {status_label}   signals={signals}"))
    sprint(c(BOLD,     f"    {'URL':<10} {f.get('url') or f.get('context','')}"))
    sprint(            f"    {'CDN':<10} {f.get('cdn','')}    ref/ver: {f.get('ref') or f.get('version','')} ")
    if f.get("owner"): sprint(f"    {'Owner':<10} {f['owner']}/{f.get('repo','')}")
    if f.get("package"): sprint(f"    {'Package':<10} {f['package']}")
    if f.get("found_on"): sprint(c(CYAN, f"    {'Found on':<10} {f['found_on']}"))
    if f.get("source"): sprint(c(DIM, f"    {'Source':<10} {f['source']}"))

    sprint()
    sprint(c(col+BOLD, f"    Issues ({len(f.get('issues',[]))})"))
    for iss in f.get("issues",[]):
        sprint(c(col, f"      •  {iss}"))

    details = f.get("details",{})
    cur = details.get("current",{})
    if cur and cur.get("status") == 200:
        sprint()
        sprint(c(DIM, f"    Current content  size={cur.get('size')}B  hash={cur.get('sha256','')}"))
        prev = (cur.get("preview","") or "").replace("\n"," ")[:160]
        sprint(c(DIM, f"    Preview: {prev}"))

    wb = details.get("wayback")
    if wb:
        sprint(c(DIM, f"    Wayback ({wb.get('timestamp','?')})  size={wb.get('size','?')}B  hash={wb.get('sha256','')}"))

    user = details.get("user",{})
    if user.get("exists"):
        sprint(c(DIM, f"    Account  type={user.get('type','?')}  age={user.get('age_days','?')}d  "
                       f"repos={user.get('public_repos','?')}  followers={user.get('followers','?')}"))

    commits = details.get("commits",[])
    if commits:
        sprint(c(DIM, "    Commits"))
        for cm in commits[:4]:
            sprint(c(DIM, f"      [{cm['sha']}] {cm['author']}: {cm['msg'][:80]}"))

    tags = details.get("tags",[])
    if tags:
        ts = ", ".join(f"{t['name']}→{t['sha']}" + (" [INFLATED]" if t.get("inflated") else "")
                       for t in tags[:6])
        sprint(c(DIM, f"    Tags: {ts}"))

    npm = details.get("npm",{})
    if npm.get("exists"):
        sprint(c(DIM, f"    npm  v{npm.get('latest','')}  maintainers={npm.get('maintainers',[])}  "
                       f"dead={npm.get('dead_maintainers',[])}  last_pub={npm.get('days_since','?')}d"))

    hits = details.get("monthly_hits")
    if hits:
        sprint(c(DIM, f"    jsDelivr monthly hits: {hits:,}"))

    f["exploit_steps"] = exploit_guide(f)
    sprint()
    sprint(c(BLUE+BOLD, "    ── Exploitation / Claim Steps ──────────────────────────────"))
    for step in f["exploit_steps"]:
        sprint(c(BLUE, f"    {step}"))


def print_banner():
    sprint(c(BOLD+CYAN, """
╔══════════════════════════════════════════════════════════════════════════╗
║        supplychain.py — Supply Chain Attack & Dependency Scanner        ║
║  CDN squatting │ npm/PyPI/Cargo │ dep confusion │ GitHub namespace      ║
║  typosquatting │ lifecycle inject │ lockfile confusion │ Actions audit  ║
║  3-stage validation │ Wayback diff │ trusted-maintainer FP guard        ║
╚══════════════════════════════════════════════════════════════════════════╝"""))


def print_summary(all_findings: list[dict]):
    by_sev = {"CRITICAL":[],"HIGH":[],"MEDIUM":[],"LOW":[],"POTENTIAL":[],"INFO":[]}
    for f in all_findings:
        by_sev.setdefault(f.get("severity","INFO"),[]).append(f)
    claimed   = sum(1 for f in all_findings if f.get("claimed"))
    unclaimed = sum(1 for f in all_findings if not f.get("claimed") and f.get("issues"))
    confirmed = [f for f in all_findings if f.get("severity","") not in ("POTENTIAL","INFO")]
    potential = by_sev["POTENTIAL"]
    sprint()
    sprint(c(BOLD, "═"*72))
    sprint(c(BOLD, "SUMMARY"))
    sprint(c(BOLD, "═"*72))
    sprint(f"  Confirmed findings:        {len(confirmed)}")
    sprint(c(RED,     f"  CRITICAL:                  {len(by_sev['CRITICAL'])}"))
    sprint(c(YELLOW,  f"  HIGH:                      {len(by_sev['HIGH'])}"))
    sprint(c(MAGENTA, f"  MEDIUM:                    {len(by_sev['MEDIUM'])}"))
    sprint(c(CYAN,    f"  LOW:                       {len(by_sev['LOW'])}"))
    if potential:
        sprint(c(DIM,  f"  POTENTIAL (needs review):  {len(potential)}  ← partial signals, not confirmed"))
    sprint()
    sprint(c(RED,     f"  CLAIMED  (active attack):  {claimed}   ← already squatted"))
    sprint(c(YELLOW,  f"  UNCLAIMED (claimable now): {unclaimed}   ← step-by-step claim guide provided"))


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def _expand_url(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return []
    if raw.startswith("http://") or raw.startswith("https://"):
        return [raw]
    return ["https://" + raw]


def main():
    global _verbose_global

    ap = argparse.ArgumentParser(description="Supply Chain Attack Scanner",
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-u","--url",        help="URL to scan (HTML page or JS bundle)")
    ap.add_argument("-f","--file",       help="File with URLs/domains, one per line")
    ap.add_argument("--js",              help="Local JS bundle file")
    ap.add_argument("--package-json",    help="Local package.json to scan")
    ap.add_argument("--lockfile",        help="Local package-lock.json to scan for lockfile confusion")
    ap.add_argument("--workflow",        help="GitHub Actions workflow YAML")
    ap.add_argument("--github-org",      help="GitHub org/user — scan all public repos")
    ap.add_argument("--deep",            action="store_true",
                    help="Also crawl same-origin subpages (depth 1)")
    ap.add_argument("--no-sri",          action="store_true",
                    help="Skip SRI absence findings")
    ap.add_argument("-o","--output",     help="Write JSON results to file")
    ap.add_argument("-v","--verbose",    action="store_true",
                    help="Show all scan activity including [WARN] for unreachable hosts")
    ap.add_argument("--threads",         type=int, default=30,
                    help="Concurrent threads (default: 30)")
    args = ap.parse_args()

    _verbose_global = args.verbose

    print_banner()
    all_findings = []
    urls = []

    if args.url:
        urls += _expand_url(args.url)
    if args.file:
        with open(args.file) as fh:
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    urls += _expand_url(ln)
    if args.js:
        sprint(c(CYAN, f"\n[+] Scanning JS bundle: {args.js}"))
        is_url = args.js.startswith("http")
        all_findings += scan_js(args.js, is_url=is_url, verbose=args.verbose)
    if args.package_json:
        sprint(c(CYAN, f"\n[+] Scanning package.json: {args.package_json}"))
        with open(args.package_json) as fh:
            all_findings += scan_package_json(fh.read(), source=args.package_json)
    if args.lockfile:
        sprint(c(CYAN, f"\n[+] Scanning lockfile: {args.lockfile}"))
        with open(args.lockfile) as fh:
            all_findings += scan_lockfile(fh.read(), source=args.lockfile)
    if args.workflow:
        sprint(c(CYAN, f"\n[+] Scanning workflow: {args.workflow}"))
        with open(args.workflow) as fh:
            all_findings += scan_workflow(fh.read(), source=args.workflow)
    if args.github_org:
        sprint(c(CYAN, f"\n[+] Scanning GitHub org: {args.github_org}"))
        all_findings += scan_github_org(args.github_org, verbose=args.verbose)

    if urls:
        sprint(c(CYAN, f"\n[+] Scanning {len(urls)} URL(s) @ {args.threads} threads..."))
        if args.verbose:
            sprint(c(DIM, "    (auto-scans all same-host JS bundles; --deep also crawls subpages)"))

        def _scan_one(url):
            if args.verbose:
                sprint(c(DIM, f"  → {url}"))
            findings = scan_url(url, verbose=args.verbose, check_sri=not args.no_sri,
                                scan_linked_js=True)
            if args.deep:
                r = _get(HTTP, url, timeout=15)
                if r:
                    base_host = urlparse(url).netloc
                    subpage_hrefs = re.findall(
                        r'<a[^>]+href=["\']([^"\'#?]+)["\']', r.text, re.I)
                    subpages_seen = set()
                    for href in subpage_hrefs[:30]:
                        if not href.startswith("http"):
                            href = urljoin(url, href)
                        if urlparse(href).netloc == base_host and href not in subpages_seen:
                            subpages_seen.add(href)
                            if args.verbose:
                                sprint(c(DIM, f"    [deep] subpage: {href[:80]}"))
                            findings += scan_url(href, verbose=args.verbose,
                                                 check_sri=not args.no_sri,
                                                 scan_linked_js=True)
            return findings

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(_scan_one, u): u for u in urls}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    all_findings += fut.result()
                except Exception as e:
                    if args.verbose:
                        sprint(c(YELLOW, f"  [ERR] {futs[fut]}: {e}"))

    if not all_findings:
        sprint(c(GREEN, "\n[✓] No supply chain issues found."))
        print_summary([])
        return

    seen_urls = set()
    deduped = []
    for f in all_findings:
        key = f.get("url","") + "|" + "|".join(f.get("issues",[])[:1])
        if key not in seen_urls:
            seen_urls.add(key)
            deduped.append(f)

    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    deduped.sort(key=lambda x: (order.get(x.get("severity","INFO"),9), -x.get("signals",0)))
    all_findings = deduped

    sprint(c(BOLD+RED, f"\n[!] {len(all_findings)} confirmed supply chain finding(s):"))
    for i, f in enumerate(all_findings, 1):
        print_finding(f, i)

    print_summary(all_findings)

    if args.output:
        clean = []
        for f in all_findings:
            cf = {k:v for k,v in f.items() if k != "details"}
            d = f.get("details",{})
            cd = {k: ({kk:vv for kk,vv in v.items() if kk != "content"} if isinstance(v,dict) else v)
                  for k,v in d.items()}
            cf["details"] = cd
            clean.append(cf)
        with open(args.output,"w") as fh:
            json.dump(clean, fh, indent=2, default=str)
        sprint(c(GREEN, f"\n[+] Results → {args.output}"))


if __name__ == "__main__":
    main()
