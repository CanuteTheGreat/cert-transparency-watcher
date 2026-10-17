# cert-transparency-watcher

Catch rogue or unexpected TLS certificates before they catch you — using the
public Certificate Transparency (CT) logs, for free, with zero signup.

Since 2018, all public CAs must log every certificate they issue to public CT
logs. This means anyone can query, in near real time, every certificate ever
issued for your domain — including ones you *didn't* request. That's exactly
how subdomain takeovers, rogue internal CAs, and CA-level misissuance get
caught early, if someone's watching.

This tool queries [crt.sh](https://crt.sh) (a free, public CT log search
service — no account, no API key) for a domain and every name under it, falls
back to [Cert Spotter](https://sslmate.com/certspotter/)'s free API when crt.sh
is down or slow, and flags:

- **Unexpected issuers** — a cert issued by a CA that isn't on your allowlist.
  Classic sign of a misissued cert, a compromised CA, or someone using a
  different provider than your team agreed on.
- **Unexpected subdomains** — a subdomain that got a cert but isn't one you
  expected. Classic early warning for subdomain takeover attempts (someone
  points a forgotten DNS record at infra they control and gets a cert for it)
  or a forgotten dev/staging host.
- **Recent activity** — even with no allowlists configured, it just lists
  everything issued in the last N days (default 30) so you have visibility.

## Why this matters

Most teams have zero visibility into what certs exist for their own domains
beyond the ones they issued themselves. CT logs already contain that data —
publicly, for free — but almost nobody looks at it until after an incident.

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/cert-transparency-watcher.git        # latest release branch; puts `cert-transparency-watcher` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/cert-transparency-watcher.git@v1.2.1  # a pinned release
brew install canutethegreat/errant-tools/cert-transparency-watcher   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/cert-transparency-watcher                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.6+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/cert_transparency_watcher.py && python3 cert_transparency_watcher.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/cert-transparency-watcher/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install cert-transparency-watcher` doesn't work until it's published there.

## Usage

```
cert-transparency-watcher example.com
cert-transparency-watcher example.com --allow-issuer "Let's Encrypt" --allow-issuer "Google Trust"
cert-transparency-watcher example.com --allow-subdomain www --allow-subdomain mail --allow-subdomain "@"
cert-transparency-watcher example.com --days 90 --json
# daily cron: only certificates new since yesterday, and tell me
cert-transparency-watcher example.com --state ~/.ct-state.json --fail-on-new \
    --webhook https://hooks.example/ct --exec 'mail -s "new cert" me@example.com'
```

- `--allow-issuer SUBSTR` (repeatable) — substrings of issuer names you expect
  (e.g. `"Let's Encrypt"`, `"Cloudflare"`, `"DigiCert"`, `"Amazon"`). Any cert
  whose issuer doesn't match any allowed substring is flagged. Omit entirely
  to just list issuers without flagging.
- `--allow-subdomain LABEL` (repeatable) — subdomain labels you expect (e.g.
  `www`, `mail`, `api`). Use `@` for the bare/apex domain and `*` for a wildcard
  certificate (`*.example.com`, valid for every subdomain; `*.dev` for `*.dev.example.com`),
  so a new wildcard cert is flagged unless you allow it. Any subdomain seen
  in a cert that isn't allowlisted is flagged. Omit entirely to just list
  subdomains without flagging.
- `--state FILE` — remember every certificate seen (one file can hold many domains).
  Only certificates **new since the last run** are shown and flagged, so a daily cron
  job doesn't re-alert on the same certs. `--fail-on-new` flags every new certificate
  even without allow lists (Cert Spotter-style "tell me about anything new").
- `--exec CMD` / `--webhook URL` — when something is flagged, run CMD (alert JSON on
  stdin, `CTW_DOMAIN`/`CTW_ALERTS` in the environment) and/or POST the JSON to URL.
  If a hook fails the exit code is 2 and the state isn't saved, so the next run
  alerts again instead of losing the alert.
- `--source auto|crtsh|certspotter` — default `auto` (crt.sh with retries, then Cert
  Spotter). `CERTSPOTTER_API_TOKEN` is sent if set (higher rate limits).
- `--days N` — only show certs issued in the last N days (default 30).
- `--json` — machine-readable output (same exit codes as the text report).
- `--crtsh-url TEMPLATE` / `--certspotter-url URL` — mirrors or local test servers.

A precertificate and its final certificate (two crt.sh rows, same serial)
are counted once.

Exit codes: `1` if anything was flagged, `0` otherwise, `2` if no CT source could be
queried or parsed, an alert hook failed, or usage was wrong. Python 3.6+.

## Real example (found while building this)

Running this against `rustinion.com` during development turned up 3 certs in
the last year: two from the expected Cloudflare/Google Trust Services pair,
and a third from Amazon (Amazon RSA 2048 M04), covering `rustinion.com` and
`www.rustinion.com`, dated 2026-08-28 -- a CA that wasn't on the allowlist we
had in mind for that domain going in. We traced it to AWS infrastructure we
control (not a compromise), but the point stands: without querying CT logs we
had no idea a third CA had issued a cert for that domain at all. That's
exactly the kind of "wait, who issued that?" moment this tool is built to
surface. Nothing beats testing a security tool against your own real domains.

## Requirements

Python 3.6+, standard library only — no pip installs, no API keys, no
external dependencies. Uses crt.sh's free public JSON API, which is a
community service and occasionally rate-limits or 502s under load — the tool
retries automatically with backoff.

## Pay what you want

Free to use, forever. If it's useful to you, there's a
[pay-what-you-want link](https://errant.solutions) — no obligation.

## License

MIT — see LICENSE.

## Tests

`tests/` exercises every option and check end-to-end (against a local server speaking crt.sh's JSON format, including 502/retry and broken-JSON responses) in Forgejo CI on
Python 3.6 and current Python; `sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).
