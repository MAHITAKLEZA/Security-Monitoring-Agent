# AI Website Security & Auto-Remediation Agent

This agent detects compromised websites:
- **SEO spam:** the Japanese keyword hack, pharma, gambling, adult and scam spam
- **cloaking:** spam shown only to Google
- **hidden content:** hidden spam pages and links
- **malicious redirects**
- **infected files:** backdoors, web shells, cloaking code and spam generators

It is being built in three phases:

| Phase | Status | Scope |
|---|---|---|
| 1. Detect | **Built** | Crawl pages, inspect WordPress content, scan files, flag suspicious URLs, write a report. **Nothing is deleted.** |
| 2. Safe remediation | **Built** | Backups, quarantine, clean-baseline restoration, approval workflow in the dashboard, post-fix verification |
| 3. Autonomous defense | **Built** | Continuous integrity monitoring, reinfection detection, root-cause investigation, automatic recovery limited to reinfections of already-approved fixes |

It runs as the **Spam & Compromise** check in the security dashboard (`python -m security_agent --serve`), or on its
own from the command line.

## Phase 1: what it detects

**Crawl (outside view, any site, no credentials).** It follows the site's links and a sample of sitemap URLs, and
loads every page twice: as a normal visitor and as Googlebot.

* **SEO spam** visible on the page, in any of the five spam families.
* **Cloaking:** spam served only to Googlebot.
* **Hidden spam:** spam text or links hidden with CSS.
* **Malicious redirects:**
  * HTTP redirects that only happen for visitors (not Googlebot), for visitors arriving from Google, or for phones
  * meta refresh redirects
  * JavaScript redirects, especially ones that check `document.referrer` or the device, or that are obfuscated
* **Spam pages in sitemaps:**
  * URLs with Japanese text or spam words
  * URLs shaped like spam-generator output
  * a sitemap on another domain declared in robots.txt
* **Spam page generators:** made-up URLs that return spam instead of a 404.

**WordPress content (application password, read-only).** It reads posts, pages, reusable blocks and templates,
including drafts and private items.

* Whole spam items.
* Spam or malicious code (external scripts, redirects, hidden links, hidden iframes) injected into real content.
* The accounts that wrote the spam, and recently created administrators.
* A spam site title, or a site address that points to another domain.

**Files (Kleza Site Guard plugin, read-only).**

* **Core integrity:** WordPress core files are compared with wordpress.org's official checksums, flagging
  modified files and unknown files in `wp-admin` or `wp-includes`.
* **Plugin integrity:** wordpress.org plugins are compared with their published checksums.
* **PHP where it doesn't belong:** in uploads, in the site root, or hidden inside `.ico` files.
* **Must-use plugins** and recently changed code.
* **Suspicious files read and checked for signatures:**
  * `eval(base64_decode(...))`, web shells, and shell commands run from request data
  * Googlebot or referrer checks (cloaking)
  * `auto_prepend_file`, and `.htaccess` rules that send search engines to a PHP script
  * spam text inside code files

**Detection is rule-based.** It needs no API key or external AI service. Optional Claude triage of borderline
items can be switched on (`--ai`, or `checks.compromise.ai: true` in config.yaml). It needs `ANTHROPIC_API_KEY`
and `pip install anthropic`, and is off by default.

## Phase 2: safe remediation

After every scan, what was found is turned into **proposed fixes** in the site's approval queue. Nothing on the
site changes until a person approves a fix.

| Fix | Used for | How it is undone |
|---|---|---|
| Move to trash | A post, page or reusable block that is entirely spam | Restored from the WordPress trash |
| Remove injected blocks | Spam or malicious code added to a real post; only the injected blocks go | Original content written back |
| Restore clean revision | Injected content that can't be separated; the newest clean revision is used | Original content written back |
| Demote account | An account created in the last 30 days that wrote spam (to subscriber) | Original roles restored |
| Quarantine file | Web shells, PHP in uploads, unknown files in core folders, PHP hidden in `.ico` files | File restored from quarantine |
| Restore official core / plugin file | Modified WordPress core files and wordpress.org plugin files, replaced with the official copy (its checksum is verified before writing) | Original restored from quarantine |
| Remove malicious lines | `.htaccess` / `.user.ini` cloaking and redirect rules, `auto_prepend_file`; the rest of the file is kept | Original restored from quarantine |
| Fix by hand | Anything that can't be changed safely, e.g. malware inside the active theme, or a stolen admin account | Not applicable |

**Approval workflow.** Proposed fixes appear in the dashboard under **Spam & Compromise > Remediation**, each
with a preview (the lines or blocks that will be removed, the revision to restore, the matched code), a risk
level, and **Approve** / **Reject** buttons. **Approve all low-risk** handles the obvious ones in one go. Every
decision is recorded in the History with who made it.

**Safety rules.** Every approved fix follows these rules:
* **Changed targets are left alone:** a fix is refused when its target changed since the scan, checked by file
  checksum or the post's modification time.
* **Backups first:** a local copy goes to `backups/<host>/` before anything changes. File changes also keep the
  original in the plugin's locked quarantine folder on the server.
* **Verified afterwards:** the post status, file checksum and spam URL (fetched as Googlebot) are checked again,
  and the result is shown as "Fixed and verified" or "Applied, not verified".
* **Undoable:** any applied fix can be undone from the dashboard.
* **Re-scan to confirm:** approving fixes starts a re-scan. Proposals whose problem is gone are marked
  "resolved". An undone fix whose problem is still there goes back to "waiting".
* **Things never changed automatically:** `wp-config.php`, the Site Guard plugin itself, and files over 5 MB.

## Phase 3: autonomous defense

Phase 3 watches the site between scans, notices when a fixed problem comes back, works out why, and (only if you
switch it on) re-applies fixes a person already approved. It lives in `defense.py` and `investigate.py` and appears
in the dashboard under **Spam & Compromise > Autonomous defense**.

**Continuous integrity monitoring.** While the dashboard server runs (`--serve`), every WordPress site with an
application password is checked every `watch_interval_minutes` (default 30), never during a full scan:
* **Files** (needs the Site Guard plugin): the file list is compared with a baseline (`state/defense/<host>.json`).
  Changes that match an official wordpress.org checksum (core and plugin updates) or one of the agent's own fixes
  are folded into the baseline. Every other changed code file is read and checked with the scan's signatures.
  Clean changes it can't explain are listed as **unexplained changes** until you click **Trust current files**.
  The first check records the baseline automatically; trust it once you know the site is clean.
* **Applied fixes**: a quarantined file must stay gone, a restored file must keep its clean checksum, a trashed or
  cleaned post must stay clean, and a demoted account must stay a subscriber.

**Reinfection detection.** A problem found again on a file, post or account whose fix is still applied is a
**reinfection**. The same infection goes back to "waiting" with the earlier fix kept in its history; a different
one on the same target is linked to the fix it undid. Remediation cards show "↻ Reinfection", when the target was
fixed, who approved it and how many times it came back. Full scans detect reinfections the same way.

**Root-cause investigation.** A new infection or a reinfection starts a read-only investigation (at most once per
`investigate_cooldown_minutes` for the same targets; **Investigate** runs one on demand). It ranks likely causes
(high / medium / low confidence), each with evidence and what to do:
* **Timeline:** other code files changed within `timeline_minutes` of the infected file.
* **Persistence:** must-use plugins, PHP in uploads, `auto_prepend_file` and handler rules, code in
  `wp-config.php`, oddly named PHP files, and infected files whose fix is still waiting for approval.
* **Accounts:** recently created administrators, and recently created application passwords.
* **Entry point:** outdated or closed plugins and themes, the plugin or theme that holds the infected file,
  an outdated WordPress core, and what the infected locations imply about the attacker's access.
* **Pattern:** reinfected within two hours (an active backdoor) or about a day later (a scheduled task).

Reports are written to `reports/site_guard/<host>/investigation-*.md|json`.

**Controlled automatic recovery.** Off by default (`defense.auto_recover`, or **Turn on** per site in the dashboard).
When it is on, a reinfection is fixed without waiting for a person only if:
* the fix it undid was **approved by a person** (never a chain started by the agent itself);
* its action is in `auto_actions` (quarantine, core/plugin file restore, config clean-up, trash, strip injected
  blocks, demote account). A returning file at a quarantined path is only quarantined again when it is the same
  file or still matches the scan's rules;
* that target was recovered automatically fewer than `max_auto_per_target` times (3) in 7 days. After that the
  agent stops and escalates, because the root cause is still there;
* the site is under `max_auto_per_day` (10) automatic recoveries in 24 hours;
* no earlier automatic fix of that target failed or couldn't be verified. A failure stops automation for that
  target until someone clicks **Allow again**.

Automatic fixes go through the same path as an approval: change check, local backup, apply, verify, undoable. They
are recorded as `auto-recovery (reinfection of <id>, first approved by <name>)`. **New infections always wait for a
person.** If a Teams webhook is set, reinfections, new infections and automatic recoveries are posted right away.

Settings (config.yaml, `checks.compromise.defense`): `enabled`, `watch_interval_minutes`, `auto_recover`,
`auto_actions`, `max_auto_per_day`, `max_auto_per_target`, `max_reads`, `ignore_paths`,
`investigate_cooldown_minutes`, `timeline_minutes`.

## Install the Site Guard plugin (file scan and file fixes)

1. In wp-admin, go to **Plugins > Add New > Upload Plugin** and upload `jp_seo_agent/wp-plugin/kleza-site-guard.zip`
   (version 1.1), then activate it. If 1.0 is installed, upload the zip again and choose **Replace current**.
2. Give the agent an **administrator's** application password: wp-admin > Users > Profile > Application
   Passwords. In the dashboard, enter it with Add Link / Edit site.

The plugin only answers authenticated administrators.
* **Reading:** it lists file checksums and returns file contents, and it redacts the database credentials, keys
  and salts from `wp-config.php` before sending it.
* **Changing files:** it only does so when the agent sends an approved fix, and only after checking that the
  file's checksum still matches what the scan saw.
* **Quarantine folder:** `wp-content/kleza-quarantine/`. Originals are stored there without an executable
  extension, and web access to the folder is denied.

Without the plugin, the crawl and WordPress content checks and fixes still work; only files aren't scanned or fixed.

## Command line

```bash
python -m pip install -r jp_seo_agent/requirements.txt
export WP_APP_PASSWORD="xxxx xxxx xxxx xxxx xxxx xxxx"      # PowerShell: $env:WP_APP_PASSWORD = "..."

python -m jp_seo_agent scan https://example.com/ --wp-user admin            # report + proposals (exit 2 on HIGH+)
python -m jp_seo_agent scan https://casino.example/ --allow-category gambling --max-pages 100

python -m jp_seo_agent queue https://example.com/ --wp-user admin           # list proposed fixes
python -m jp_seo_agent approve https://example.com/ <id> [<id>...] --wp-user admin
python -m jp_seo_agent reject https://example.com/ <id> --wp-user admin
python -m jp_seo_agent undo https://example.com/ <id> --wp-user admin

python -m jp_seo_agent watch https://example.com/ --wp-user admin --once     # one integrity check (exit 2 on a new problem)
python -m jp_seo_agent watch https://example.com/ --wp-user admin --interval 15 --auto-recover
python -m jp_seo_agent investigate https://example.com/ --wp-user admin      # root-cause investigation
python -m jp_seo_agent trust-baseline https://example.com/ --wp-user admin   # current files become the baseline
python -m jp_seo_agent auto-recover https://example.com/ on --wp-user admin  # or off
```

The command line and the dashboard share the same queue (`state/remediation/<host>.json`).

Options:
* `--site-language ja`, `--allow-path /ja/`, `--allow-category <family>`: say what content is legitimate on the site.
* `--max-pages N`: how many pages to crawl.
* `--no-file-scan`: skip the file scan.
* `--ai`: also let Claude triage borderline items (optional, needs an API key).
* `--wp-credentials-file secrets/site.env`: read the WordPress username and password from a file.

Reports go to `reports/site_guard/<host>/`:
* `scan-*.md` / `scan-*.json`: the findings
* `spam-urls-*.txt`: confirmed spam URLs plus suspicious ones

> Git Bash on Windows rewrites arguments such as `--page /`. Run `export MSYS_NO_PATHCONV=1` first, or use PowerShell.

## Limits

* Cloaking that verifies Google's IP addresses (not just the User-Agent) can't be seen from outside. The file
  scan looks for that code instead, and Search Console's URL Inspection shows what Google actually got.
* A file scan needs the plugin, and only reads the 80 most suspicious files in full. The rest are checked by
  checksum and location.
* Plugins that aren't on wordpress.org have no published checksums, so only their suspicious files are read.
