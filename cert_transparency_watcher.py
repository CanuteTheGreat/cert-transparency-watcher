#!/usr/bin/env python3
"""
cert-transparency-watcher — catch rogue/unexpected TLS certs before they catch you.

Queries the public Certificate Transparency logs (via crt.sh's free JSON API — no
API key, no signup) for a domain and flags:
  - Certificates issued by an issuer CA you didn't put on your allowlist
    (classic sign of a misissued/rogue cert or a CA compromise)
  - Subdomains that showed up in a cert but aren't in your expected-subdomains list
    (classic early warning for subdomain takeover attempts, or a forgotten
    dev/staging host someone spun up TLS for)
  - Certs issued in the last N days (default 30) so you can review recent activity
    even if nothing looks obviously wrong yet

Zero cost, zero dependencies beyond the Python standard library + internet access.
Run it by hand, or drop it in cron for a daily/weekly check.

Usage:
    python3 cert_transparency_watcher.py example.com
    python3 cert_transparency_watcher.py example.com --allow-issuer "Let's Encrypt" --allow-issuer "DigiCert Inc"
    python3 cert_transparency_watcher.py example.com --allow-subdomain www --allow-subdomain mail --days 90
    python3 cert_transparency_watcher.py example.com --json
"""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone

CRTSH_URL = "https://crt.sh/?q={}&output=json"


def fetch_certs(domain, timeout=20, retries=4):
    import time
    url = CRTSH_URL.format(urllib.parse.quote(f"%.{domain}"))
    req = urllib.request.Request(url, headers={"User-Agent": "cert-transparency-watcher/1.0"})
    raw = ""
    last_err = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            if raw.strip():
                break
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            last_err = e
        time.sleep(2 * (attempt + 1))  # crt.sh is a free community service and rate-limits/502s
                                        # under load; back off and retry rather than failing hard
    else:
        pass
    if not raw.strip():
        if last_err:
            print(f"ERROR: could not reach crt.sh after {retries} attempts: {last_err}", file=sys.stderr)
            sys.exit(2)
        return []
    # crt.sh sometimes returns concatenated JSON objects instead of a clean array
    # under load; be defensive.
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        fixed = "[" + raw.replace("}{", "},{") + "]"
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            print("ERROR: could not parse crt.sh response", file=sys.stderr)
            sys.exit(2)


def extract_subdomain(name_value, domain):
    name_value = name_value.strip().lower()
    if name_value.startswith("*."):
        name_value = name_value[2:]
    if name_value == domain:
        return "@"
    if name_value.endswith("." + domain):
        return name_value[: -(len(domain) + 1)]
    return None  # unrelated name in SAN list (e.g. multi-domain cert)


def main():
    ap = argparse.ArgumentParser(description="Monitor Certificate Transparency logs for a domain")
    ap.add_argument("domain", help="Domain to watch, e.g. example.com")
    ap.add_argument("--allow-issuer", action="append", default=[],
                     help="Substring of an issuer CA name considered expected (repeatable). "
                          "If omitted, all issuers are reported without flagging.")
    ap.add_argument("--allow-subdomain", action="append", default=[],
                     help="Subdomain label considered expected, e.g. 'www' or 'mail' (repeatable). "
                          "'@' means the bare domain. If omitted, all subdomains are reported without flagging.")
    ap.add_argument("--days", type=int, default=30, help="Only show certs issued in the last N days (default 30)")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text")
    args = ap.parse_args()

    domain = args.domain.lower().strip()
    entries = fetch_certs(domain)

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    seen = {}  # dedupe by (name, issuer, entry_timestamp) since crt.sh returns one row per log entry

    results = []
    for e in entries:
        try:
            ts = datetime.strptime(e.get("not_before", "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if ts < cutoff:
            continue
        issuer = e.get("issuer_name", "unknown")
        names = set()
        for line in (e.get("name_value") or "").splitlines():
            names.add(line.strip().lower())
        key = (frozenset(names), issuer, e.get("id"))
        if key in seen:
            continue
        seen[key] = True

        subs = set()
        for n in names:
            s = extract_subdomain(n, domain)
            if s is not None:
                subs.add(s)

        issuer_flagged = bool(args.allow_issuer) and not any(a.lower() in issuer.lower() for a in args.allow_issuer)
        unexpected_subs = set()
        if args.allow_subdomain:
            allowed_lower = {a.lower() for a in args.allow_subdomain}
            unexpected_subs = {s for s in subs if s not in allowed_lower}

        results.append({
            "id": e.get("id"),
            "issued": e.get("not_before"),
            "issuer": issuer,
            "names": sorted(names),
            "subdomains": sorted(subs),
            "issuer_flagged": issuer_flagged,
            "unexpected_subdomains": sorted(unexpected_subs),
        })

    results.sort(key=lambda r: r["issued"] or "", reverse=True)

    if args.json:
        print(json.dumps({"domain": domain, "days": args.days, "certs": results}, indent=2))
        return

    print(f"cert-transparency-watcher: {domain} — {len(results)} cert(s) in the last {args.days} day(s)\n")
    flags = 0
    for r in results:
        marker = ""
        reasons = []
        if r["issuer_flagged"]:
            reasons.append(f"unexpected issuer: {r['issuer']}")
        if r["unexpected_subdomains"]:
            reasons.append(f"unexpected subdomain(s): {', '.join(r['unexpected_subdomains'])}")
        if reasons:
            marker = "  ⚠️  " + " | ".join(reasons)
            flags += 1
        print(f"[{r['issued']}] issuer={r['issuer']}")
        print(f"    names: {', '.join(r['names'])}{marker}")

    print()
    if flags:
        print(f"⚠️  {flags} cert(s) flagged for review. Not necessarily malicious — could be a new")
        print("    provider, a forgotten subdomain, or a legit CA you haven't allowlisted yet.")
        print("    But worth a look: unexpected certs are the first sign of subdomain takeover")
        print("    or CA-level misissuance.")
        sys.exit(1)
    else:
        print("No flags. (Note: flags only trigger if you passed --allow-issuer/--allow-subdomain —")
        print("without those, this just lists recent cert activity for review.)")


if __name__ == "__main__":
    main()
