# Security Monitoring Agent: indexly.ai

A command-line agent that scans **https://indexly.ai/** for security issues and writes detailed reports.
It has **no dashboard and sends no alerts**. Each run writes JSON and Markdown reports to disk and prints a short console summary.

## What it checks

| Check (`--checks` name) | What it does |
|---|---|
| `ssl` | Certificate validity and chain, expiry (warns at 30 days, critical at 7), weak or legacy TLS, certificate/issuer changes between runs, HTTP→HTTPS redirect |
| `headers` | HSTS, CSP quality, clickjacking (XFO / frame-ancestors), nosniff, Referrer-Policy, Permissions-Policy, COOP, version disclosure (`Server`, `X-Powered-By`), cookie flags, CORS wildcard |
| `exposed_files` | About 45 sensitive paths (`.env*`, `.git`, backups, SQL dumps, keys, phpinfo, `docker-compose.yml`, directory listings, `.next/BUILD_ID`) plus public JS source maps. Hits are confirmed by file content and compared against the soft-404 page to avoid false positives. |
| `changes` | Baseline of each configured page: new third-party **script or iframe origins**, external form targets, title/meta changes, removed security headers, HTTP status, redirects, and visible-text similarity |
| `malware` | Obfuscated `eval`/`document.write` payloads, crypto miners, card-skimmer patterns, web-shell signatures, hidden external iframes, SEO spam, and blacklist lookups (Spamhaus DBL, SURBL, optional Google Safe Browsing) for the site and its third-party script domains |
| `vulnerabilities` | Outdated server software (for example `nginx/1.18.0`), vulnerable or end-of-life JS libraries, mixed content, forms that post over HTTP, dangerous HTTP methods, CORS origin reflection, verbose errors, `security.txt`, sensitive `robots.txt` entries |
| `dns` | SPF, DMARC, CAA, DNSSEC, NS/MX/A record changes (hijack indicators), domain expiry and transfer lock via RDAP |
| `third_party` | Inventory of third-party domains, missing Subresource Integrity, scripts from unapproved domains (optional allowlist), third-party domains that no longer resolve (takeover risk) |
| `wordpress` | Off by default, enabled per site. Public: REST API username enumeration, XML-RPC `system.multicall`, `readme.html`, core version against wordpress.org. With an **Application Password**: outdated/closed/abandoned/inactive plugins and themes, known plugin CVEs (optional WPScan token), administrator count and guessable admin usernames, stale application passwords, Site Health security tests |

## Sites
It is currently set up to monitor only **indexly.ai**. To monitor more sites later, add entries under `targets:` in [config.yaml](config.yaml):
```yaml
targets:
  - name: indexly
    url: https://indexly.ai/
    domain: indexly.ai
  - name: shop
    url: https://www.example-shop.com/
    pages: [/, /login, /checkout]
    checks:                       # optional per-site overrides
      exposed_files: { enabled: false }
  - https://another-site.com/     # short form
```
Each site gets its own baseline (`state/<name>.json`) and reports (`reports/<name>/`). With more than one site, `reports/summary.md` gives a combined overview.

## Setup

### 1. Prerequisites
- **Python 3.9 or newer** (developed and tested on 3.13). Check with `python --version`.
- **pip** (bundled with Python). Check with `pip --version`.
- Internet access, so the agent can reach the sites it scans and the reputation/version services it queries (wordpress.org, RDAP, Spamhaus/SURBL, and optionally Google Safe Browsing / WPScan).
- No database or web server is required — reports are plain files and the dashboard is a self-contained HTML page.

### 2. Get the code
Download or clone this project, then open a terminal in the project folder (the one containing `requirements.txt`).

### 3. (Recommended) Create a virtual environment
Keeps these packages isolated from the rest of your system.

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope Process RemoteSigned, then re-run
```

**macOS / Linux (bash):**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

You'll know it worked when your prompt shows `(.venv)`. Use `deactivate` to leave it later.

### 4. Install the packages
```bash
python -m pip install --upgrade pip        # optional, gets the latest pip
python -m pip install -r requirements.txt
```

This installs everything the agent needs:

| Package | Version | Used for |
|---|---|---|
| [`requests`](https://pypi.org/project/requests/) | `>=2.31` | All HTTP/HTTPS requests: fetching pages, probing files, headers, WordPress REST API, blacklist and Safe Browsing lookups |
| [`dnspython`](https://pypi.org/project/dnspython/) | `>=2.4` | DNS lookups for the `dns` check (SPF, DMARC, CAA, NS/MX/A records) and the Spamhaus/SURBL domain-blacklist checks |
| [`PyYAML`](https://pypi.org/project/PyYAML/) | `>=6.0` | Reading `config.yaml` |
| [`openpyxl`](https://pypi.org/project/openpyxl/) | `>=3.1` | Writing the Excel (`.xlsx`) report for each scan |

Everything else the agent uses (HTTP server for the dashboard, JSON, SSL, threading, TLS/certificate parsing) is part of the Python standard library — nothing extra to install.

To install without a virtual environment, just run step 4. On some Linux systems use `pip3` instead of `pip`, or add `--user` if you can't write to the system site-packages.

### 5. Verify the install
```bash
python -m security_agent --list-sites
```
If it prints the configured sites (or "no sites") without an `ImportError`, the packages are installed correctly.

> **Note:** you may see a `RequestsDependencyWarning` about `urllib3`/`charset_normalizer` versions on some systems. It's harmless; to silence it, run `python -m pip install --upgrade requests urllib3 charset_normalizer`.

### Optional integrations (no install needed, just set an environment variable)
These enable extra checks and are read from environment variables at runtime:

| Variable | Enables |
|---|---|
| `KLEZA_WP_APP_PASSWORD` (or a per-site `app_password_file`) | Authenticated WordPress scan and inside malware scan |

## Usage

```bash
python -m security_agent                    # one scan of every configured site
python -m security_agent --list-sites       # show configured sites
python -m security_agent --site indexly     # only one configured site
python -m security_agent --url https://x.com --url https://y.com   # ad-hoc sites
python -m security_agent --checks ssl,dns   # only some checks
python -m security_agent --loop             # continuous: every schedule.interval_minutes (default 60)
python -m security_agent --loop --interval 30
python -m security_agent --accept-changes   # approve the current site as the new baseline
python -m security_agent -v                 # verbose logging
```

### Interactive dashboard
```bash
python -m security_agent --serve            # live dashboard at http://127.0.0.1:8765; scans every site daily at schedule.daily_at (09:00)
python -m security_agent --serve --loop     # dashboard + scans every interval_minutes instead of daily
python -m security_agent --dashboard        # rebuild reports/dashboard.html from existing reports (no scan) and open it
```
Every scan also regenerates `reports/dashboard.html`, a single self-contained file that works offline.

Pages (sidebar):
- **Dashboard**: cards for links monitored, safe links, links with warnings and high-risk links, a Security Checks Overview chart (passing, warning and failing per check), a Risk Distribution donut, Recent Alerts, the **Analysed Links** table with a pass/warn/fail icon per check (search, Scan All, View Report), and Key Benefits.
- **Link Analysis**: every link with all nine checks. Click a link for its full report: risk score, change since the last scan, SSL and domain expiry, check cards, trend charts, a findings table you can filter and search (with evidence), and recommendations.
- **Reports**: the latest report for each link (.md / .json downloads) and the full scan history, where each scan links to its archived report.
- **Alerts**: every Medium or higher issue across all links, filterable by severity, link, check or text. (These are shown in the dashboard only. Nothing is sent anywhere.)
- **Settings**: monitored websites (add or remove), scan interval, which checks are enabled, and the theme (system, light or dark).

**Add Link** (live mode) adds a website from the page and can scan it right away. Sites added this way are saved in `sites.json`, and `config.yaml` is never rewritten. Sites defined in `config.yaml` can only be removed there.

WordPress issues can be fixed from their cards (Update, Remove, Delete); see [Fixing WordPress issues from the dashboard](#fixing-wordpress-issues-from-the-dashboard).

The server listens only on `127.0.0.1`. Scan requests need a custom header and are checked by `Host`, so other websites you visit can't trigger scans.

**Exit codes:** `0` means OK. `2` means the worst finding is at or above `report.fail_on` (default `HIGH`), which is useful in cron jobs or CI.

### WordPress application password (authenticated scan)
1. In wp-admin, go to **Users > Profile > Application Passwords**, enter a name (e.g. `Security Monitor`) and click **Add New Application Password**. Use an administrator account, because the plugin, user and Site Health checks need one.
2. Put the username in `config.yaml` under the site's `checks.wordpress.username` (kleza.io is already set up).
3. Put the password in the environment variable named by `app_password_env`, never in `config.yaml`:
   ```powershell
   setx KLEZA_WP_APP_PASSWORD "abcd efgh ijkl mnop qrst uvwx"   # new terminals only
   $env:KLEZA_WP_APP_PASSWORD = "abcd efgh ijkl mnop qrst uvwx"  # current terminal
   ```
4. Run `python -m security_agent --site kleza.io --checks wordpress`.

Instead of the environment variable you can put the credentials in the file named by `app_password_file`
(kleza.io uses `secrets/kleza.io.env`, and the `secrets/` folder is git-ignored; copy `secrets/kleza.io.env.example` to start):
```
username=your-wp-admin-user
password=abcd efgh ijkl mnop qrst uvwx
```

**Malware inside scan.** With these credentials the `malware` check also scans the site from inside through the REST API
(read-only): posts, pages, drafts and private items, reusable blocks, templates, navigation menus and widgets
(for obfuscated code, injected scripts, hidden iframes, hidden spam links and spam keywords), media uploads
(PHP/HTML/JS files, SVGs with script), recently created or new administrators, unidentified or newly installed plugins,
and a site address pointing to another domain. The results appear in the dashboard's Malware column as "Inside scan: …".
Theme and plugin PHP files can't be read over the REST API, so a file-level scan needs SFTP/SSH or a server-side scanner.

The password is sent only over HTTPS, only to the site's own REST API, and never written to reports or state files. Scans are read-only (GET only); the site is changed only when you click a fix button in the dashboard (below). Optionally set `WPSCAN_API_TOKEN` (free at wpscan.com) to report known plugin vulnerabilities.

### Fixing WordPress issues from the dashboard
In live mode (`--serve`), WordPress issue cards on a link's check page get a button that makes the change on the site with the
saved application password. Nothing else is needed: no wp-admin login, no extra plugin, no SSH or FTP.

| Issue | Button | What it does |
|---|---|---|
| Outdated plugin / outdated theme / vulnerable plugin with a fixed version | **Update** | Updates it to the latest version from wordpress.org, then checks that the version changed |
| Plugin removed from wordpress.org, vulnerable plugin with no fix, possibly abandoned plugin | **Remove** | Deactivates and deletes the plugin (asks first) |
| Inactive plugins installed | **Delete** | Deletes every inactive plugin (asks first, listing them) |

On success the card disappears and the site is rescanned to confirm. On failure the card stays and shows WordPress's reason.
Every card also has **Ignore**, which hides the issue for good (restore it under Settings).

- **Update needs the Hostinger AI Assistant plugin active on the site.** The WordPress REST API has no update command, so
  updates run through that plugin's `hostinger-ai/plugin-update` and `hostinger-ai/theme-update` abilities
  (`/wp-json/wp-abilities/v1/`). On sites without it, Update shows an error saying so. Premium plugins that aren't on
  wordpress.org (e.g. Monarch) can't be updated this way.
- **Remove and Delete use the core REST API** (`/wp/v2/plugins`) and work on any WordPress site. Deleting a plugin runs its
  uninstall routine, which usually removes its settings too.
- The application password must belong to an **administrator**.
- Issues with no button (WordPress core updates, inactive themes, XML-RPC, `readme.html`, security headers, SSL, DNS) need
  server or file access, which the application password doesn't give.

### Change detection workflow
The first run records a baseline. After that, every deviation is reported **on every run until you approve it** with `--accept-changes`, so a single report can't hide an injected script.
To have the baseline follow the live site automatically instead, set `checks.changes.auto_update_baseline: true`.

### Scheduling without `--loop`
Windows Task Scheduler (hourly):
```powershell
schtasks /Create /SC HOURLY /TN "IndexlySecurityMonitor" /TR "cmd /c cd /d C:\Mahi\Kleza\Security-Monitoring-Agent && python -m security_agent"
```
Linux cron:
```
0 * * * * cd /opt/security-agent && python3 -m security_agent >> monitor.log 2>&1
```

## Output

```
reports/
  summary.md / summary.json          # all sites at a glance (when more than one site)
  indexly/
    latest.json / latest.md          # most recent scan
    history.jsonl                    # one line per scan: status, risk score, counts
    20260923-101500/report.json|md   # every scan archived
state/indexly.json                   # baselines: certificate, DNS records, page snapshots
```

Each report contains the **security status** (SECURE / GOOD / NEEDS ATTENTION / AT RISK / CRITICAL), a **risk score** (0–100), a **risk summary** by severity and by check, deduplicated **recommendations**, and **detailed findings** with evidence.

## Notes
- Scans are passive or low-impact: ordinary GET/OPTIONS requests at 4-way concurrency, with no exploitation or fuzzing. Only scan sites you own or are authorized to test.
- Spamhaus refuses queries sent through large public DNS resolvers (8.8.8.8, 1.1.1.1). The report notes when that happens.
- Add pages to `target.pages` in `config.yaml` (for example `/pricing`, `/login`) to baseline and scan them too.
