#!/usr/bin/env python3
"""
cert-transparency-watcher — catch rogue/unexpected TLS certs before they catch you.

Queries the public Certificate Transparency logs for a domain and every name
under it -- via crt.sh's free JSON API, falling back to Cert Spotter's free
API when crt.sh is down (no API key, no signup) -- and flags:
  - Certificates issued by an issuer CA you didn't put on your allowlist
    (classic sign of a misissued/rogue cert or a CA compromise)
  - Subdomains that showed up in a cert but aren't in your expected-subdomains list
    (classic early warning for subdomain takeover attempts, or a forgotten
    dev/staging host someone spun up TLS for)
  - Certs issued in the last N days (default 30) so you can review recent activity

With --state FILE it remembers what it has already seen, so a daily cron job
only reports (and alerts on) certificates that are new since the last run;
--exec runs a command and --webhook POSTs JSON when something needs attention.

Zero cost, zero dependencies beyond the Python standard library + internet access.

Usage:
    cert-transparency-watcher example.com
    cert-transparency-watcher example.com --allow-issuer "Let's Encrypt" --allow-issuer "DigiCert Inc"
    cert-transparency-watcher example.com --allow-subdomain www --allow-subdomain mail --days 90
    cert-transparency-watcher example.com --state ~/.ct-state.json --fail-on-new --webhook https://hooks.example/ct
    cert-transparency-watcher example.com --json

Exit codes: 0 = nothing flagged, 1 = flagged (new, with --state) certificates,
2 = CT sources unreachable/unparseable, an alert hook failed, or bad usage.
"""
__version__ = "1.2.0"

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

CRTSH_URL = "https://crt.sh/?q={}&output=json"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
UA = "cert-transparency-watcher/%s (+https://errant.solutions)" % __version__


class FetchError(Exception):
    pass


def _get(url, timeout, headers=None):
    req = urllib.request.Request(url, headers=dict({"User-Agent": UA}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_crtsh(domain, timeout=20, retries=4, url_template=CRTSH_URL, sleep=time.sleep):
    url = url_template.format(urllib.parse.quote("%.{}".format(domain)))
    raw, last_err = "", None
    for attempt in range(retries):
        try:
            raw = _get(url, timeout)
            if raw.strip():
                break
        except (urllib.error.URLError, OSError) as e:
            # OSError also covers raw socket resets/timeouts mid-read, which
            # urllib does not always wrap in URLError.
            last_err = e
        if attempt < retries - 1:
            sleep(2 * (attempt + 1))  # crt.sh is a free community service and rate-limits/502s under load
    if not raw.strip():
        if last_err:
            raise FetchError("could not reach crt.sh after {} attempts: {}".format(retries, last_err))
        return []
    # crt.sh sometimes returns concatenated JSON objects instead of a clean array under load
    try:
        return json.loads(raw)
    except ValueError:
        try:
            return json.loads("[" + raw.replace("}{", "},{") + "]")
        except ValueError:
            raise FetchError("could not parse crt.sh response")


def fetch_certspotter(domain, url=CERTSPOTTER_URL, timeout=30, max_pages=20):
    """Cert Spotter's issuances API, mapped onto crt.sh's field names."""
    token = os.environ.get("CERTSPOTTER_API_TOKEN")
    headers = {"Authorization": "Bearer " + token} if token else {}
    out, after = [], None
    for _ in range(max_pages):
        q = {"domain": domain, "include_subdomains": "true", "expand": ["dns_names", "issuer"]}
        if after:
            q["after"] = after
        try:
            data = json.loads(_get(url + "?" + urllib.parse.urlencode(q, doseq=True), timeout, headers))
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise FetchError("Cert Spotter: {}".format(e))
        if not data:
            break
        for e in data:
            issuer = e.get("issuer") or {}
            out.append({"id": e.get("id"), "issuer_name": issuer.get("name") or issuer.get("friendly_name") or "unknown",
                        "name_value": "\n".join(e.get("dns_names") or []),
                        "not_before": (e.get("not_before") or "").replace("Z", ""),
                        "not_after": (e.get("not_after") or "").replace("Z", ""),
                        "serial_number": e.get("tbs_sha256") or e.get("cert_sha256") or e.get("id")})
        after = data[-1].get("id")
    return out


def fetch_certs(domain, source, crtsh_url, certspotter_url):
    """Returns (entries, source used). auto = crt.sh first, Cert Spotter if crt.sh fails."""
    errors = []
    if source in ("auto", "crtsh"):
        try:
            return fetch_crtsh(domain, url_template=crtsh_url), "crt.sh"
        except FetchError as e:
            errors.append(str(e))
            if source == "crtsh":
                raise
    try:
        return fetch_certspotter(domain, certspotter_url), "Cert Spotter"
    except FetchError as e:
        errors.append(str(e))
    raise FetchError("; ".join(errors))


def extract_subdomain(name_value, domain):
    """'www.example.com' -> 'www', 'example.com' -> '@', '*.example.com' -> '*' (a wildcard is
    valid for every subdomain, so it is its own label, never the apex), '*.dev.example.com' ->
    '*.dev'; names outside the domain -> None."""
    name_value = name_value.strip().lower().rstrip(".")
    if name_value == domain:
        return "@"
    if name_value == "*." + domain:
        return "*"
    if name_value.endswith("." + domain):
        return name_value[: -(len(domain) + 1)]
    return None  # unrelated name in SAN list (e.g. multi-domain cert)


def cert_key(issuer, serial, names):
    return "{}|{}".format(issuer.strip().lower(), str(serial or ",".join(sorted(names))).lower())


def load_state(path, domain):
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise FetchError("can't read --state {}: {}".format(path, e))
    return (data.get("domains") or {}).get(domain, {})


def save_state(path, domain, seen):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    data.setdefault("domains", {})[domain] = seen
    data["version"] = 1
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ct-state-")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def run_hooks(args, payload):
    body = json.dumps(payload, indent=2)
    if args.exec_cmd:
        env = dict(os.environ, CTW_DOMAIN=payload["domain"], CTW_ALERTS=str(len(payload["alerts"])))
        p = subprocess.run(args.exec_cmd, shell=True, input=body, universal_newlines=True, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            raise FetchError("--exec command exited {}: {}".format(p.returncode, (p.stderr or "").strip()[-300:]))
    if args.webhook:
        req = urllib.request.Request(args.webhook, data=body.encode(), method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                r.read()
        except (urllib.error.URLError, OSError) as e:
            raise FetchError("--webhook POST failed: {}".format(e))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cert-transparency-watcher", description="Monitor Certificate Transparency logs for a domain",
                                 epilog="Exit codes: 0 nothing flagged, 1 flagged certificates, 2 CT/hook failure or bad usage.")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("domain", help="Domain to watch, e.g. example.com (every name under it is included)")
    ap.add_argument("--allow-issuer", action="append", default=[],
                    help="Substring of an issuer CA name considered expected (repeatable). "
                         "If omitted, all issuers are reported without flagging.")
    ap.add_argument("--allow-subdomain", action="append", default=[],
                    help="Subdomain label considered expected, e.g. 'www' or 'mail' (repeatable). "
                         "'@' means the bare domain, '*' a wildcard certificate for every subdomain ('*.dev' for "
                         "*.dev.<domain>). If omitted, all subdomains are reported without flagging.")
    ap.add_argument("--days", type=int, default=30, help="Only show certs issued in the last N days (default 30)")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text")
    ap.add_argument("--source", choices=["auto", "crtsh", "certspotter"], default="auto",
                    help="CT data source (default: crt.sh, falling back to Cert Spotter)")
    ap.add_argument("--state", metavar="FILE",
                    help="remember seen certificates here; only certificates new since the last run are flagged")
    ap.add_argument("--fail-on-new", action="store_true",
                    help="with --state: treat every new certificate as flagged, even without allow lists")
    ap.add_argument("--exec", dest="exec_cmd", metavar="CMD",
                    help="run CMD (shell) when something is flagged; the alert JSON is on stdin, "
                         "CTW_DOMAIN/CTW_ALERTS in the environment")
    ap.add_argument("--webhook", metavar="URL", help="POST the alert JSON to URL when something is flagged")
    ap.add_argument("--crtsh-url", default=CRTSH_URL, metavar="TEMPLATE",
                    help="crt.sh-compatible JSON endpoint, '{}' is replaced by the query "
                         "(default: %(default)s) -- for a mirror or a local test server")
    ap.add_argument("--certspotter-url", default=CERTSPOTTER_URL, metavar="URL",
                    help="Cert Spotter issuances endpoint (default: %(default)s; CERTSPOTTER_API_TOKEN is sent if set)")
    args = ap.parse_args(argv)
    if args.fail_on_new and not args.state:
        ap.error("--fail-on-new needs --state")

    domain = args.domain.lower().strip().rstrip(".")
    try:
        seen = load_state(args.state, domain) if args.state else None
        entries, source = fetch_certs(domain, args.source, args.crtsh_url, args.certspotter_url)
    except FetchError as e:
        print("ERROR: {}".format(e), file=sys.stderr)
        return 2

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    dedupe = set()  # crt.sh returns one row per log entry (precert + final cert)
    results = []
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_seen = dict(seen or {})
    for e in entries:
        try:
            ts = datetime.strptime((e.get("not_before") or "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if ts < cutoff:
            continue
        issuer = e.get("issuer_name", "unknown")
        names = {line.strip().lower() for line in (e.get("name_value") or "").splitlines() if line.strip()}
        key = cert_key(issuer, e.get("serial_number") or e.get("id"), names)
        if key in dedupe:
            continue
        dedupe.add(key)
        subs = {s for s in (extract_subdomain(n, domain) for n in names) if s is not None}
        issuer_flagged = bool(args.allow_issuer) and not any(a.lower() in issuer.lower() for a in args.allow_issuer)
        unexpected = set()
        if args.allow_subdomain:
            allowed = {a.lower() for a in args.allow_subdomain}
            unexpected = {s for s in subs if s not in allowed}
        is_new = seen is None or key not in seen
        new_seen.setdefault(key, now_iso)
        flagged = bool(issuer_flagged or unexpected or (args.fail_on_new and is_new))
        results.append({"id": e.get("id"), "issued": e.get("not_before"), "issuer": issuer, "names": sorted(names),
                        "subdomains": sorted(subs), "issuer_flagged": issuer_flagged,
                        "unexpected_subdomains": sorted(unexpected), "new": is_new,
                        "flagged": flagged and is_new})

    results.sort(key=lambda r: r["issued"] or "", reverse=True)
    alerts = [r for r in results if r["flagged"]]
    payload = {"domain": domain, "source": source, "days": args.days, "alerts": alerts}

    if alerts and (args.exec_cmd or args.webhook):
        try:
            run_hooks(args, payload)
        except FetchError as e:
            print("ERROR: {} (state not updated, so the next run alerts again)".format(e), file=sys.stderr)
            return 2
    if args.state:
        try:
            save_state(args.state, domain, new_seen)
        except OSError as e:
            print("ERROR: can't write --state {}: {}".format(args.state, e), file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps({"version": __version__, "domain": domain, "source": source, "days": args.days,
                          "flagged": len(alerts), "new": sum(1 for r in results if r["new"]) if args.state else None,
                          "certs": results}, indent=2))
        return 1 if alerts else 0

    shown = [r for r in results if r["new"]] if args.state else results
    label = " new since the last run" if args.state else ""
    print("cert-transparency-watcher: {} — {} cert(s){} in the last {} day(s) (source: {})\n".format(
        domain, len(shown), label, args.days, source))
    for r in shown:
        reasons = []
        if r["issuer_flagged"]:
            reasons.append("unexpected issuer: {}".format(r["issuer"]))
        if r["unexpected_subdomains"]:
            reasons.append("unexpected subdomain(s): {}".format(", ".join(r["unexpected_subdomains"])))
        if args.fail_on_new and r["new"] and not reasons:
            reasons.append("new certificate")
        marker = ("  ⚠️  " + " | ".join(reasons)) if reasons and r["flagged"] else ""
        print("[{}] issuer={}".format(r["issued"], r["issuer"]))
        print("    names: {}{}".format(", ".join(r["names"]), marker))
    print()
    if alerts:
        print("⚠️  {} cert(s) flagged for review. Not necessarily malicious — could be a new".format(len(alerts)))
        print("    provider, a forgotten subdomain, or a legit CA you haven't allowlisted yet.")
        print("    But worth a look: unexpected certs are the first sign of subdomain takeover")
        print("    or CA-level misissuance.")
        return 1
    print("No flags. (Note: flags only trigger if you passed --allow-issuer/--allow-subdomain"
          + ("/--fail-on-new" if args.state else "") + " —")
    print("without those, this just lists recent cert activity for review.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
