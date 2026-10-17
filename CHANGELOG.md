# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.0 - 2026-10-16

- **`--state FILE`**: remembers every certificate seen, so only certificates new since the last run are shown and
  flagged (no daily re-alerts from cron); `--fail-on-new` flags any new certificate even without allow lists.
- **Cert Spotter fallback** when crt.sh is down or slow (`--source auto|crtsh|certspotter`, `CERTSPOTTER_API_TOKEN`).
- **Alert hooks**: `--exec CMD` (JSON on stdin) and `--webhook URL` (JSON POST) when something is flagged; a failing
  hook exits 2 and leaves the state unchanged so the alert is retried.
- JSON output carries `source`, `new` per certificate and the tool version.
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/cert-transparency-watcher.git`
  puts a `cert-transparency-watcher` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- --json now exits 1 when something is flagged; dedupe precerts; add CI tests

## 1.0.0 - 2026-09-16

- First public release.
