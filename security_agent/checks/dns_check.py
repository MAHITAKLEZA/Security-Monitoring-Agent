"""DNS & domain checks: SPF, DMARC, CAA, DNSSEC, record changes (hijack indicators), registration expiry/locks."""

from datetime import datetime, timezone

import dns.exception
import dns.resolver
import requests

from ..models import Finding, Severity as S

NAME = "dns"
TRACKED = {"A": S.LOW, "AAAA": S.LOW, "NS": S.HIGH, "MX": S.MEDIUM}


def _resolver():
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    return resolver


def _records(resolver, name, rtype):
    try:
        answer = resolver.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return None
    if rtype == "TXT":
        return sorted(b"".join(r.strings).decode(errors="replace") for r in answer)
    return sorted(r.to_text().lower() for r in answer)


def _email_auth(resolver, domain):
    findings = []
    spf = [t for t in (_records(resolver, domain, "TXT") or []) if t.lower().startswith("v=spf1")]
    if not spf:
        findings.append(Finding(NAME, "No SPF record", S.MEDIUM, f"{domain} has no v=spf1 TXT record",
                                "Publish SPF, e.g. 'v=spf1 include:<your mail provider> -all' (or 'v=spf1 -all' if "
                                "the domain sends no mail) to prevent spoofing."))
    elif len(spf) > 1:
        findings.append(Finding(NAME, "Multiple SPF records (SPF permerror)", S.MEDIUM, " | ".join(spf),
                                "Merge into a single SPF record."))
    else:
        record = spf[0].lower()
        if "+all" in record:
            findings.append(Finding(NAME, "SPF allows any sender (+all)", S.HIGH, spf[0], "Use -all or ~all."))
        elif "?all" in record or not record.rstrip().endswith("all"):
            findings.append(Finding(NAME, "SPF policy is neutral/permissive", S.LOW, spf[0], "End SPF with -all or ~all."))

    dmarc = [t for t in (_records(resolver, f"_dmarc.{domain}", "TXT") or []) if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        findings.append(Finding(NAME, "No DMARC record", S.MEDIUM, f"_dmarc.{domain} missing",
                                "Publish DMARC, e.g. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "'."))
    elif "p=none" in dmarc[0].lower().replace(" ", ""):
        findings.append(Finding(NAME, "DMARC policy is p=none (monitor only)", S.LOW, dmarc[0],
                                "Move to p=quarantine or p=reject once reports look clean."))
    return findings


def _registration(domain, warn_days):
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=15, headers={"Accept": "application/rdap+json"})
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return [Finding(NAME, "Domain registration data unavailable (RDAP)", S.INFO, str(exc)[:200])]
    findings = []
    expiry = next((e["eventDate"] for e in data.get("events", []) if e.get("eventAction") == "expiration"), None)
    if expiry:
        expires = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            sev = S.CRITICAL
        elif days <= 14:
            sev = S.HIGH
        elif days <= warn_days:
            sev = S.MEDIUM
        else:
            sev = S.INFO
        findings.append(Finding(NAME, f"Domain registration expires in {days} days", sev, f"Expires {expires:%Y-%m-%d}",
                                "Enable auto-renew with the registrar." if sev > S.INFO else ""))
    statuses = [s.lower() for s in data.get("status", [])]
    if statuses and not any("transfer prohibited" in s for s in statuses):
        findings.append(Finding(NAME, "Domain transfer lock not enabled", S.LOW, ", ".join(statuses),
                                "Enable registrar transfer lock (clientTransferProhibited) to prevent hijacking."))
    return findings


def run(ctx, cfg, state):
    st = state.setdefault(NAME, {})
    resolver = _resolver()
    domain = ctx.domain
    findings = []

    current = {}
    for rtype, severity in TRACKED.items():
        records = _records(resolver, domain if rtype in ("NS", "MX") else ctx.host, rtype)
        if records is None:
            findings.append(Finding(NAME, f"DNS {rtype} lookup timed out", S.LOW, domain))
            continue
        current[rtype] = records
        previous = st.get(rtype)
        if previous is not None and previous != records:
            findings.append(Finding(NAME, f"DNS {rtype} records changed", severity,
                                    f"{', '.join(previous) or '(none)'} -> {', '.join(records) or '(none)'}",
                                    "Confirm this change was made by your team. Unexpected NS/MX/A changes are a "
                                    "strong indicator of DNS or domain hijacking.",
                                    {"previous": previous, "current": records}))
    if not current.get("A") and not current.get("AAAA"):
        findings.append(Finding(NAME, f"{ctx.host} does not resolve", S.CRITICAL, "", "Check DNS configuration."))
    st.update(current)

    findings.extend(_email_auth(resolver, domain))

    if not _records(resolver, domain, "CAA"):
        findings.append(Finding(NAME, "No CAA record", S.LOW, "Any CA may issue certificates for this domain.",
                                f"Add CAA records, e.g. {domain}. CAA 0 issue \"letsencrypt.org\"."))
    if not _records(resolver, domain, "DNSKEY"):
        findings.append(Finding(NAME, "DNSSEC not enabled", S.INFO, "No DNSKEY records found.",
                                "Enable DNSSEC at your DNS provider and registrar to prevent DNS spoofing."))

    findings.extend(_registration(domain, cfg.get("domain_expiry_warning_days", 45)))
    findings.append(Finding(NAME, "DNS snapshot", S.INFO, "", evidence=current))
    return findings
