# Supply Chain Audit
 
> Supply chain attack surface scanner — CDN namespace squatting, dependency takeover, typosquatting, lifecycle injection, lockfile confusion, and GitHub Actions audit. Every finding is validated through a 3-stage pipeline before output.
 
Built for HackerOne bug bounty research. Produces exploitation-ready reports with step-by-step claim guides, Wayback Machine content diffs, and jsDelivr reach statistics.
 
---
 
## Detection coverage
 
| Vector | Severity | What it checks |
|---|---|---|
| CDN namespace squatting | CRITICAL | jsDelivr `gh/` + `npm/`, unpkg, esm.sh, skypack, jspm, raw.githubusercontent.com, deno.land/x, GitHub Gists — unclaimed owner, repo, or package |
| Lifecycle script injection | CRITICAL | `postinstall` / `preinstall` / `prepare` hooks containing `curl`, `wget`, `bash`, `eval`, backticks — install-time RCE on `npm install` |
| Malicious content | CRITICAL | `sendBeacon` / `Image.src` / WebSocket exfil, cryptominers, obfuscated `eval(atob(...))`, 10+ `String.fromCharCode` chains, PoC squatter markers |
| Sourcemap exfil | HIGH | `//# sourceMappingURL` pointing to attacker-controlled infrastructure |
| Typosquatting | HIGH | Levenshtein distance 1 against top 100 npm packages — catches `expresss`, `lodassh`, `reakt` etc. |
| Dead maintainer accounts | HIGH | npm maintainer usernames that no longer exist — anyone who registers them gains publish rights |
| Lockfile confusion | HIGH | `package-lock.json` `resolved` URLs pointing to non-npmjs.org registries — internal mirror poisoning |
| GitHub Actions unpinned | HIGH / MEDIUM | Third-party actions using `@main`, `@master` (HIGH) or mutable tags instead of full commit SHA (MEDIUM) |
| Unclaimed GitHub Actions | CRITICAL | Action repo does not exist — create and tag to hijack every pipeline using it |
| Content replacement | CRITICAL | Wayback Machine archive vs current content — >70% size drop = likely supply chain swap |
| Tag inflation | HIGH | Multiple version tags pointing to same commit SHA — squatters fake version history to win `@latest` resolution |
| npm scope squatting | HIGH | `@scope/pkg` where `@scope` is not registered on npm |
| Dep confusion | HIGH | Internal-looking package names (`@corp/`, `-internal`, `-private`) that don't exist on public npm |
| CNAME / GCS bucket takeover | HIGH | Domains pointing to unclaimed GCS buckets via GCP Load Balancer A records |
| Unpublished packages | HIGH | npm packages that were published then unpublished — slot claimable |
| Floating refs | LOW | `@master`, `@latest`, `@main` CDN refs with no SRI hash — any push propagates immediately |
| Dead CDN infrastructure | MEDIUM | rawgit.com, gitcdn.xyz, wzrd.in, npmcdn.com — retired hosts with unknown redirect behaviour |
| Missing SRI | LOW | `<script src="...">` loading from CDN without `integrity=` attribute on floating/raw refs |
 
---
 
## Installation
 
```bash
git clone https://github.com/ShadowByte1/chain-audit
cd chain-audit
pip install requests dnspython
```
 
Set a GitHub token to raise API rate limits from 60 to 5000 req/hr:
 
```bash
export GITHUB_TOKEN=ghp_yourtoken
```
 
---
 
## Usage
 
**Scan a live URL** — fetches HTML, auto-crawls same-origin JS bundles:
 
```bash
python3 supplychain.py -u https://target.com/
```
 
**Scan a list of URLs or domains:**
 
```bash
python3 supplychain.py -f urls.txt
```
 
**Deep crawl** — also follows same-origin `<a href>` links one level deep:
 
```bash
python3 supplychain.py -u https://target.com/ --deep
```
 
**Scan a local or remote JS bundle directly:**
 
```bash
python3 supplychain.py --js bundle.js
python3 supplychain.py --js https://target.com/assets/app.js
```
 
**Scan a `package.json`** — dep confusion, lifecycle hooks, GitHub source refs:
 
```bash
python3 supplychain.py --package-json package.json
```
 
**Scan a `package-lock.json`** — lockfile confusion, non-standard registries:
 
```bash
python3 supplychain.py --lockfile package-lock.json
```
 
**Audit a GitHub Actions workflow:**
 
```bash
python3 supplychain.py --workflow .github/workflows/deploy.yml
```
 
**Scan an entire GitHub org** — all public repos, workflows, Pages sites:
 
```bash
python3 supplychain.py --github-org targetorg
```
 
**Write JSON results:**
 
```bash
python3 supplychain.py -u https://target.com/ -o results.json
```
 
---
 
## CLI flags
 
| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | — | URL to scan (HTML page or JS bundle) |
| `-f`, `--file` | — | File of URLs or bare domains, one per line |
| `--js` | — | Local JS file or remote URL to scan directly |
| `--package-json` | — | `package.json` to scan for dep confusion and lifecycle hooks |
| `--lockfile` | — | `package-lock.json` to scan for lockfile confusion |
| `--workflow` | — | GitHub Actions YAML to audit |
| `--github-org` | — | GitHub org or user — scans all public repos |
| `--deep` | off | Follow same-origin links one level (depth 1) |
| `--no-sri` | off | Skip SRI absence findings |
| `-o`, `--output` | — | Write JSON results to file |
| `-v`, `--verbose` | off | Show per-URL activity and `[WARN]` for unreachable hosts |
| `--threads` | 30 | Concurrent worker threads |
 
---
 
## Example output
 
```
╔══════════════════════════════════════════════════════════════════════════╗
║        supplychain.py — Supply Chain Attack & Dependency Scanner        ║
╚══════════════════════════════════════════════════════════════════════════╝
 
[+] Scanning 1 URL(s) @ 30 threads...
 
────────────────────────────────────────────────────────────────────────
🔴  [CRITICAL]  Finding #1   CLAIMED / ACTIVE ATTACK   signals=6
    URL        https://cdn.jsdelivr.net/gh/squatter/fake-lib@master/dist/lib.js
    CDN        jsdelivr-gh    ref/ver: master
    Owner      squatter/fake-lib
    Found on   https://target.com/
 
    Issues (4)
      •  ACCOUNT AGE 12d: 'squatter' created less than 6 months ago (followers=0)
      •  SQUATTER FINGERPRINT: 0 stars, 0 followers, new account
      •  FLOATING REF: @master is mutable — any push propagates to all sites
      •  MALICIOUS CONTENT (1 signal(s)): PoC squatter marker — console.log("supply-chain-poc")
 
    Current content  size=42B  hash=3f9a1c2d8e4b7f01
    Preview: console.log("supply-chain-poc")
    Account  type=User  age=12d  repos=1  followers=0
 
    ── Exploitation / Claim Steps ──────────────────────────────
    [ ACTIVE ATTACK — GitHub namespace squatted, serving malicious content ]
 
    Step 1 — Verify the malicious CDN response is live:
      curl -si 'https://cdn.jsdelivr.net/gh/...' -H 'User-Agent: hackerone-shadowbyte'
    Step 2 — Confirm squatter identity via GitHub commit history:
      curl -s 'https://api.github.com/repos/squatter/fake-lib/commits' | python3 -m json.tool
    Step 3 — Report to GitHub Security:
      https://github.com/contact/report-abuse
 
════════════════════════════════════════════════════════════════════════
SUMMARY
════════════════════════════════════════════════════════════════════════
  Confirmed findings:        3
  CRITICAL:                  1
  HIGH:                      2
  MEDIUM:                    0
  LOW:                       0
 
  CLAIMED  (active attack):  1   ← already squatted
  UNCLAIMED (claimable now): 2   ← step-by-step claim guide provided
```
 
---
 
## Validation pipeline
 
Every CDN dependency goes through three stages before a finding is emitted:
 
**Stage 1 — DNS / registry ownership**
Resolves GitHub user/org/repo existence via API, checks npm package registry, validates scope registration, detects NXDOMAIN on gist owners. Severity is set here based on account age, follower count, star count, suspicious commit messages, and tag inflation patterns.
 
**Stage 2 — Live content fetch**
Fetches the CDN URL twice for consistency. Runs malicious content detection (exfil vectors, cryptominers, obfuscation, PoC markers, sourcemap exfil). Fetches the closest Wayback Machine snapshot and compares size and SHA-256 hash. Checks jsDelivr stale cache (CDN 200 vs raw.githubusercontent.com 404). Queries jsDelivr monthly hit stats.
 
**Stage 3 — Confidence threshold**
Requires minimum signal count by severity tier. INFO/LOW findings need ≥2 signals or they are emitted as POTENTIAL. MEDIUM requires ≥1. Trusted maintainer guard: accounts with age >2yr, followers >500, and repo stars >500 have content-change findings downgraded to informational — legitimate library updates are not reported as active attacks.
 
---
 
## False positive handling
 
The scanner applies a trusted maintainer guard to suppress false positives on established projects. A floating `@master` ref combined with a Wayback content hash change on `paulirish/lite-youtube-embed` (31K followers, 6335 days old) is a library update, not a supply chain attack.
 
Thresholds: account age >730 days AND followers >500 AND repo stars >500. All three must pass. Findings on trusted accounts that contain only floating-ref and content-change signals are downgraded from HIGH/CLAIMED to LOW/informational with a note to pin to a version tag.
 
---
 
## Severity reference
 
| Severity | Meaning |
|---|---|
| CRITICAL | Active attack or immediately claimable namespace with confirmed exploit path |
| HIGH | Strong signals — unclaimed package, dead maintainer, unpinned action on deleted repo |
| MEDIUM | Moderate risk — dead CDN, retired infrastructure, archived action repo |
| LOW | Informational — floating ref, missing SRI, trusted-maintainer content change |
| POTENTIAL | Partial signals only — requires manual verification before reporting |
 
---
 
## Responsible disclosure
 
This tool is built for authorised bug bounty research and penetration testing. Do not use it against targets outside your scope. PoC claims should use `console.log("supply-chain-poc-shadowbyte")` — never deploy actual malware. Report findings via the program's responsible disclosure channel.
 
---
 
## Author
 
**Shadowbyte** — OSCP | HackerOne researcher | [github.com/ShadowByte1](https://github.com/ShadowByte1)
