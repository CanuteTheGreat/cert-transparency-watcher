"""Detection accuracy: a curated CT corpus where every certificate's verdict is known.

Each entry below is a realistic crt.sh row with the verdict a careful human would give for an
organisation that expects Let's Encrypt / Google Trust Services certificates for www, mail,
api and the apex: anything else (another CA, an unexpected or deeper name, a wildcard nobody
asked for) must be flagged (false negative otherwise) and everything expected must not be
(false positive otherwise). Rows outside the time window, precertificate duplicates, names
of other domains and malformed rows must neither be flagged nor counted.
"""
import datetime
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "cert_transparency_watcher.py")
LE = "C=US, O=Let's Encrypt, CN=R11"
GTS = "C=US, O=Google Trust Services, CN=WR1"
DIGI = "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"
ROGUE = "C=CN, O=Some Other CA Co, CN=Some Other DV CA"


def ago(days):
    return (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")


# (id, names, issuer, age in days, serial, expected: None = not listed, else set of reasons)
CORPUS = [
    (1, ["corp.test", "www.corp.test"], LE, 2, "01", set()),
    (2, ["mail.corp.test"], GTS, 5, "02", set()),
    (3, ["API.corp.test"], LE, 9, "03", set()),                          # upper case in the log
    (4, ["www.corp.test"], DIGI, 4, "04", {"issuer"}),                   # expected name, unexpected CA
    (5, ["staging.corp.test"], LE, 6, "05", {"subdomain"}),              # forgotten host
    (6, ["*.corp.test"], LE, 3, "06", {"subdomain"}),                    # a wildcard nobody asked for
    (7, ["corp.test", "*.corp.test"], GTS, 1, "07", {"subdomain"}),      # wildcard next to the apex
    (8, ["a.b.www.corp.test"], LE, 8, "08", {"subdomain"}),              # deeper than any allowed label
    (9, ["login.corp.test"], ROGUE, 7, "09", {"issuer", "subdomain"}),   # classic phishing setup
    (10, ["shop.othercompany.test", "www.corp.test"], LE, 10, "10", set()),  # unrelated SAN ignored
    (11, ["vpn.corp.test"], LE, 45, "11", None),                         # outside --days 30
    (12, ["api.corp.test"], LE, 1, "12", set()),
    (13, ["api.corp.test"], LE, 1, "12", None),                          # precert duplicate of 12
    (14, ["www.corp.test."], LE, 2, "14", set()),                        # trailing dot (FQDN form)
    (15, ["*.dev.corp.test"], LE, 2, "15", {"subdomain"}),
]
BAD_ROWS = [{"id": 99, "issuer_name": LE, "name_value": "www.corp.test", "not_before": "not a date",
             "serial_number": "99"}]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        rows = [{"issuer_ca_id": 1, "issuer_name": iss, "common_name": names[0], "name_value": "\n".join(names),
                 "id": i, "not_before": ago(age), "not_after": ago(-60), "serial_number": serial}
                for i, names, iss, age, serial, _ in CORPUS] + BAD_ROWS
        data = json.dumps(rows).encode()
        self.send_response(200)
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
    p = subprocess.run([sys.executable, TOOL, "--crtsh-url", URL, "--json", "corp.test"] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
    return p.returncode, json.loads(p.stdout)


ALLOW = ["--allow-issuer", "Let's Encrypt", "--allow-issuer", "Google Trust Services",
         "--allow-subdomain", "@", "--allow-subdomain", "www", "--allow-subdomain", "mail", "--allow-subdomain", "api"]


class TestCorpus(unittest.TestCase):
    def test_verdicts(self):
        code, out = run(*ALLOW)
        got = {c["id"]: c for c in out["certs"]}
        listed = {i for i, *_rest, exp in CORPUS if exp is not None}
        self.assertEqual(set(got), listed, "listed certificates")
        for i, names, iss, age, serial, exp in CORPUS:
            if exp is None:
                continue
            with self.subTest(cert=i, names=names):
                c = got[i]
                reasons = set()
                if c["issuer_flagged"]:
                    reasons.add("issuer")
                if c["unexpected_subdomains"]:
                    reasons.add("subdomain")
                self.assertEqual(reasons, exp)
                self.assertEqual(c["flagged"], bool(exp))
        self.assertEqual(out["flagged"], sum(1 for *_r, exp in CORPUS if exp))
        self.assertEqual(code, 1)

    def test_everything_expected_allowed_is_clean(self):
        allow = ALLOW + ["--allow-issuer", "DigiCert", "--allow-issuer", "Some Other CA",
                         "--allow-subdomain", "staging", "--allow-subdomain", "*", "--allow-subdomain", "a.b.www",
                         "--allow-subdomain", "login", "--allow-subdomain", "*.dev"]
        code, out = run(*allow)
        self.assertEqual([c["id"] for c in out["certs"] if c["flagged"]], [])
        self.assertEqual(code, 0)

    def test_state_only_alerts_once(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        try:
            code1, first = run("--state", path, *ALLOW)
            code2, second = run("--state", path, *ALLOW)
            code3, third = run("--state", path, "--fail-on-new")
        finally:
            os.unlink(path)
        self.assertEqual((code1, first["flagged"]), (1, sum(1 for *_r, exp in CORPUS if exp)))
        self.assertEqual((code2, second["flagged"], second["new"]), (0, 0, 0))
        self.assertEqual((code3, third["flagged"]), (0, 0))  # nothing is new on the third run either


if __name__ == "__main__":
    unittest.main()
