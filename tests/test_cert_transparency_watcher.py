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
import subprocess
import sys
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

STATE = {"fail_first": 0, "calls": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
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


def tearDownModule():
    SERVER.shutdown()


def run(*args):
    return subprocess.run([sys.executable, TOOL, "--crtsh-url", URL] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)


def run_json(*args):
    p = run("--json", *args)
    return p.returncode, json.loads(p.stdout)


class TestWatcher(unittest.TestCase):
    def setUp(self):
        STATE["fail_first"] = 0
        STATE["calls"] = 0

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
        self.assertEqual(STATE["calls"], 4)

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
        for opt in ("--allow-issuer", "--allow-subdomain", "--days", "--json", "--crtsh-url"):
            self.assertIn(opt, p.stdout)


if __name__ == "__main__":
    unittest.main()
