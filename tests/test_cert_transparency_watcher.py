"""End-to-end tests for cert_transparency_watcher.py.

crt.sh can't be run locally, so a local HTTP server serves crt.sh-format
JSON (field layout copied from a real crt.sh response) and the tool is
pointed at it with --crtsh-url. The tool itself runs unmodified as a
subprocess over real HTTP, including the retry/backoff and broken-response
paths that crt.sh produces under load.
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "cert_transparency_watcher.py")


def days_ago(n):
    return (datetime.datetime.utcnow() - datetime.timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%S")


def entry(id_, names, issuer, age_days, serial=None):
    return {"issuer_ca_id": 1, "issuer_name": issuer, "common_name": names[0], "name_value": "\n".join(names),
            "id": id_, "not_before": days_ago(age_days), "not_after": days_ago(-60),
            "serial_number": serial or ("%032x" % id_), "result_count": 2}


LE = "C=US, O=Let's Encrypt, CN=R11"
GTS = "C=US, O=Google Trust Services, CN=WE1"
ODD = "C=XX, O=Unexpected CA Ltd, CN=Odd Issuing CA"
EXAMPLE = [
    entry(1, ["example.test", "www.example.test"], LE, 3),
    entry(2, ["*.example.test", "example.test"], GTS, 10),
    entry(3, ["staging.example.test"], ODD, 5),
    entry(4, ["mail.example.test", "other-customer.test"], LE, 20),
    entry(5, ["old.example.test"], LE, 200),
    # precertificate + final certificate: two crt.sh rows, one certificate
    entry(6, ["api.example.test"], LE, 1, serial="abc123"),
    entry(7, ["api.example.test"], LE, 1, serial="abc123"),
]

STATE = {"fail_first": 0, "calls": 0, "spotter": "down", "spotter_calls": 0, "hooks": [], "hook_status": 200}
SPOTTER = [  # Cert Spotter issuances (expand=dns_names,issuer), two pages
    [{"id": "9001", "tbs_sha256": "aa11", "dns_names": ["example.test", "www.example.test"],
      "not_before": days_ago(2) + "Z", "not_after": days_ago(-80) + "Z", "issuer": {"name": LE}},
     {"id": "9002", "tbs_sha256": "bb22", "dns_names": ["vpn.example.test"],
      "not_before": days_ago(4) + "Z", "not_after": days_ago(-80) + "Z", "issuer": {"name": ODD}}],
    [{"id": "9003", "tbs_sha256": "cc33", "dns_names": ["old.example.test"],
      "not_before": days_ago(300) + "Z", "not_after": days_ago(-10) + "Z", "issuer": {"name": LE}}],
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        STATE["hooks"].append((self.path, self.headers.get("Content-Type"), json.loads(self.rfile.read(n))))
        self.send_response(STATE["hook_status"])
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/certspotter"):
            STATE["spotter_calls"] += 1
            q = parse_qs(urlparse(self.path).query)
            if STATE["spotter"] != "up" or q.get("domain") != ["example.test"]:
                self.send_response(503)
                self.end_headers()
                return
            assert q["include_subdomains"] == ["true"] and sorted(q["expand"]) == ["dns_names", "issuer"]
            page = {None: 0, "9002": 1}.get(q.get("after", [None])[0], 2)
            data = json.dumps(SPOTTER[page] if page < len(SPOTTER) else []).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        STATE["calls"] += 1
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if STATE["fail_first"] > 0:
            STATE["fail_first"] -= 1
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Bad Gateway")
            return
        domain = q[2:] if q.startswith("%.") else q
        if domain == "example.test":
            body = json.dumps(EXAMPLE)
        elif domain == "concat.test":  # crt.sh under load: objects glued together, no array
            body = "".join(json.dumps(entry(i, [f"h{i}.concat.test"], LE, 1)) for i in (10, 11))
        elif domain == "garbage.test":
            body = "<html>not json</html>"
        elif domain == "empty.test":
            body = "[]"
        else:
            self.send_response(500)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def setUpModule():
    global SERVER, URL
    SERVER = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=SERVER.serve_forever, daemon=True).start()
    URL = "http://127.0.0.1:%d/?q={}&output=json" % SERVER.server_address[1]
    global SPOTTER_URL, HOOK_URL
    SPOTTER_URL = "http://127.0.0.1:%d/certspotter" % SERVER.server_address[1]
    HOOK_URL = "http://127.0.0.1:%d/hook" % SERVER.server_address[1]


def tearDownModule():
    SERVER.shutdown()


def run(*args):
    return subprocess.run([sys.executable, TOOL, "--crtsh-url", URL, "--certspotter-url", SPOTTER_URL] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)


def run_json(*args):
    p = run("--json", *args)
    return p.returncode, json.loads(p.stdout)


class TestWatcher(unittest.TestCase):
    def setUp(self):
        STATE.update(fail_first=0, calls=0, spotter="down", spotter_calls=0, hooks=[], hook_status=200)

    def test_lists_recent_certs_without_flags(self):
        code, out = run_json("example.test")
        self.assertEqual(code, 0)
        ids = [c["id"] for c in out["certs"]]
        self.assertEqual(sorted(ids), [1, 2, 3, 4, 6])  # #5 too old; #6/#7 one cert
        self.assertEqual(out["flagged"], 0)
        by_id = {c["id"]: c for c in out["certs"]}
        self.assertEqual(by_id[2]["subdomains"], ["@"])                 # *.example.test -> apex label
        self.assertEqual(by_id[4]["subdomains"], ["mail"])              # unrelated SAN ignored
        self.assertEqual(out["certs"][0]["id"], 6)                      # newest first

    def test_days_option(self):
        _, out = run_json("example.test", "--days", "365")
        self.assertIn(5, [c["id"] for c in out["certs"]])
        _, out = run_json("example.test", "--days", "4")
        self.assertEqual(sorted(c["id"] for c in out["certs"]), [1, 6])

    def test_allow_issuer_flags_unexpected_ca(self):
        code, out = run_json("example.test", "--allow-issuer", "Let's Encrypt", "--allow-issuer", "google trust")
        self.assertEqual(code, 1)
        flagged = [c["id"] for c in out["certs"] if c["issuer_flagged"]]
        self.assertEqual(flagged, [3])

    def test_allow_subdomain_flags_unexpected_names(self):
        code, out = run_json("example.test", "--allow-subdomain", "www", "--allow-subdomain", "@",
                             "--allow-subdomain", "API", "--allow-subdomain", "mail")
        self.assertEqual(code, 1)
        flagged = {c["id"]: c["unexpected_subdomains"] for c in out["certs"] if c["unexpected_subdomains"]}
        self.assertEqual(flagged, {3: ["staging"]})

    def test_text_report_and_exit_code(self):
        p = run("example.test", "--allow-issuer", "Let's Encrypt", "--allow-issuer", "Google")
        self.assertEqual(p.returncode, 1)
        self.assertIn("example.test — 5 cert(s) in the last 30 day(s)", p.stdout)
        self.assertIn("unexpected issuer: " + ODD, p.stdout)
        self.assertIn("1 cert(s) flagged for review", p.stdout)
        p = run("example.test")
        self.assertEqual(p.returncode, 0)
        self.assertIn("No flags.", p.stdout)

    def test_retries_through_transient_502s(self):
        STATE["fail_first"] = 2
        code, out = run_json("example.test")
        self.assertEqual(code, 0)
        self.assertEqual(len(out["certs"]), 5)
        self.assertEqual(STATE["calls"], 3)

    def test_gives_up_with_exit_2(self):
        STATE["fail_first"] = 99
        p = run("example.test")
        self.assertEqual(p.returncode, 2)
        self.assertIn("could not reach crt.sh after 4 attempts", p.stderr)
        self.assertIn("Cert Spotter", p.stderr)  # the fallback was tried too, and it's down
        self.assertEqual(STATE["calls"], 4)
        p = run("example.test", "--source", "crtsh")
        self.assertEqual(p.returncode, 2)
        self.assertNotIn("Cert Spotter", p.stderr)

    def test_concatenated_objects_are_repaired(self):
        code, out = run_json("concat.test")
        self.assertEqual(sorted(c["id"] for c in out["certs"]), [10, 11])

    def test_unparseable_response_exit_2(self):
        p = run("garbage.test")
        self.assertEqual(p.returncode, 2)
        self.assertIn("could not parse crt.sh response", p.stderr)

    def test_no_certs(self):
        code, out = run_json("Empty.Test.")
        self.assertEqual(code, 0)
        self.assertEqual(out["domain"], "empty.test")
        self.assertEqual(out["certs"], [])

    def test_help(self):
        p = subprocess.run([sys.executable, TOOL, "--help"], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(p.returncode, 0)
        for opt in ("--allow-issuer", "--allow-subdomain", "--days", "--json", "--crtsh-url", "--state",
                    "--source", "--exec", "--webhook", "--fail-on-new"):
            self.assertIn(opt, p.stdout)


class TestFallbackStateAndHooks(unittest.TestCase):
    def setUp(self):
        STATE.update(fail_first=0, calls=0, spotter="down", spotter_calls=0, hooks=[], hook_status=200)
        self.tmp = tempfile.mkdtemp()
        self.state = os.path.join(self.tmp, "ct-state.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cert_spotter_fallback_and_source_option(self):
        STATE.update(fail_first=99, spotter="up")
        code, out = run_json("example.test", "--allow-issuer", "Let's Encrypt")
        self.assertEqual(out["source"], "Cert Spotter")
        self.assertEqual(sorted(c["id"] for c in out["certs"]), ["9001", "9002"])  # 9003 older than 30 days
        self.assertEqual(code, 1)
        self.assertEqual([c["id"] for c in out["certs"] if c["issuer_flagged"]], ["9002"])
        self.assertEqual(STATE["spotter_calls"], 3)  # two pages + the empty one that ends paging
        STATE.update(fail_first=0, calls=0)
        code, out = run_json("example.test", "--source", "certspotter")
        self.assertEqual(out["source"], "Cert Spotter")
        self.assertEqual(STATE["calls"], 0)

    def test_state_reports_only_new_certificates(self):
        args = ("example.test", "--allow-issuer", "Let's Encrypt", "--allow-issuer", "Google", "--state", self.state)
        code, out = run_json(*args)
        self.assertEqual((code, out["flagged"], out["new"]), (1, 1, 5))  # first run: everything is new
        with open(self.state) as f:
            self.assertEqual(len(json.load(f)["domains"]["example.test"]), 5)
        code, out = run_json(*args)
        self.assertEqual((code, out["flagged"], out["new"]), (0, 0, 0))  # same certs: nothing re-alerts
        self.assertFalse(any(c["new"] for c in out["certs"]))
        EXAMPLE.append(entry(8, ["new-thing.example.test"], ODD, 0))
        try:
            code, out = run_json(*args)
            p = run(*args)
        finally:
            EXAMPLE.pop()
        self.assertEqual((code, out["flagged"], out["new"]), (1, 1, 1))
        self.assertEqual([c["id"] for c in out["certs"] if c["new"]], [8])
        self.assertIn("0 cert(s) new since the last run", p.stdout)  # the JSON run already recorded #8

    def test_fail_on_new(self):
        code, _ = run_json("example.test", "--state", self.state, "--fail-on-new")
        self.assertEqual(code, 1)
        code, _ = run_json("example.test", "--state", self.state, "--fail-on-new")
        self.assertEqual(code, 0)
        self.assertEqual(run("example.test", "--fail-on-new").returncode, 2)  # needs --state

    def test_exec_and_webhook_alerts(self):
        out_file = os.path.join(self.tmp, "alert.json")
        cmd = "cat > %s; echo \"$CTW_DOMAIN $CTW_ALERTS\" >> %s.env" % (out_file, out_file)
        code, _ = run_json("example.test", "--allow-issuer", "Let's Encrypt", "--allow-issuer", "Google",
                           "--exec", cmd, "--webhook", HOOK_URL)
        self.assertEqual(code, 1)
        with open(out_file) as f:
            alert = json.load(f)
        self.assertEqual([a["id"] for a in alert["alerts"]], [3])
        with open(out_file + ".env") as f:
            self.assertEqual(f.read().strip(), "example.test 1")
        self.assertEqual(len(STATE["hooks"]), 1)
        path, ctype, body = STATE["hooks"][0]
        self.assertEqual((path, ctype), ("/hook", "application/json"))
        self.assertEqual(body["alerts"][0]["issuer"], ODD)
        # nothing flagged: no hook calls
        STATE["hooks"] = []
        run_json("example.test", "--webhook", HOOK_URL)
        self.assertEqual(STATE["hooks"], [])

    def test_failed_hook_is_exit_2_and_keeps_alerting(self):
        STATE["hook_status"] = 500
        args = ("example.test", "--allow-issuer", "Let's Encrypt", "--allow-issuer", "Google",
                "--state", self.state, "--webhook", HOOK_URL)
        p = run(*args)
        self.assertEqual(p.returncode, 2)
        self.assertIn("state not updated", p.stderr)
        self.assertFalse(os.path.exists(self.state))
        STATE["hook_status"] = 200
        self.assertEqual(run(*args).returncode, 1)  # the alert wasn't lost
        self.assertEqual(run("example.test", "--exec", "exit 3", "--allow-issuer", "nobody").returncode, 2)

    def test_version(self):
        p = subprocess.run([sys.executable, TOOL, "--version"], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertRegex(p.stdout, r"^cert-transparency-watcher \d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
