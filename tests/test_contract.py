"""The parts of the tool's contract the scenario tests don't pin (found as mutation-testing survivors):
what goes over the wire to crt.sh / Cert Spotter / the webhook, how Cert Spotter records are read,
dedupe and name normalisation edge cases, the --state file, hook isolation, error messages and the
--help text users read. The tool runs unmodified as a subprocess against a local HTTP server.
"""
import datetime
import json
import os
import re
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
with open(TOOL) as _f:
    VERSION = re.search(r'^__version__ = "(.*)"', _f.read(), re.M).group(1)
UA = "cert-transparency-watcher/%s (+https://errant.solutions)" % VERSION
LE = "C=US, O=Let's Encrypt, CN=R11"


def ago(days):
    return (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")


CRTSH = {}      # domain -> crt.sh JSON rows
SPOTTER = {}    # domain -> list of Cert Spotter pages
REQUESTS = []   # (method, path, headers, body)
HOOK_STATUS = [200]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        REQUESTS.append(("POST", self.path, dict(self.headers), self.rfile.read(n).decode()))
        self._reply(HOOK_STATUS[0])

    def do_GET(self):
        REQUESTS.append(("GET", self.path, dict(self.headers), ""))
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/spotter":
            pages = SPOTTER.get(q.get("domain", [""])[0])
            if pages is None:
                return self._reply(503)
            after = q.get("after", [None])[0]
            idx = 0 if after is None else 1 + [p[-1]["id"] for p in pages].index(after)
            return self._reply(200, json.dumps(pages[idx] if idx < len(pages) else []).encode())
        domain = q.get("q", [""])[0]
        domain = domain[2:] if domain.startswith("%.") else domain
        if domain not in CRTSH:
            return self._reply(502, b"Bad Gateway")
        self._reply(200, json.dumps(CRTSH[domain]).encode())


def setUpModule():
    global SERVER, BASE
    SERVER = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=SERVER.serve_forever, daemon=True).start()
    BASE = "http://127.0.0.1:%d" % SERVER.server_address[1]


def tearDownModule():
    SERVER.shutdown()
    SERVER.server_close()


def run(*args, env=None):
    e = dict(os.environ)
    e.pop("CERTSPOTTER_API_TOKEN", None)
    e.update(env or {})
    return subprocess.run([sys.executable, TOOL, "--crtsh-url", BASE + "/crtsh?q={}&output=json",
                           "--certspotter-url", BASE + "/spotter"] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=e, timeout=120)


def run_json(*args, **kw):
    p = run("--json", *args, **kw)
    return p, json.loads(p.stdout)


class Base(unittest.TestCase):
    def setUp(self):
        CRTSH.clear()
        SPOTTER.clear()
        del REQUESTS[:]
        HOOK_STATUS[0] = 200
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestWire(Base):
    def test_crtsh_request_identifies_the_tool(self):
        CRTSH["wire.test"] = []
        p, out = run_json("wire.test")
        self.assertEqual((p.returncode, out["source"]), (0, "crt.sh"))
        self.assertEqual(len(REQUESTS), 1)
        method, path, headers, _ = REQUESTS[0]
        self.assertEqual(parse_qs(urlparse(path).query)["q"], ["%.wire.test"])
        self.assertEqual(headers.get("User-Agent"), UA)

    def test_certspotter_token_is_sent_only_when_set(self):
        SPOTTER["wire.test"] = [[]]
        for env, want in (({}, None), ({"CERTSPOTTER_API_TOKEN": "tok-123"}, "Bearer tok-123")):
            del REQUESTS[:]
            p, out = run_json("wire.test", "--source", "certspotter", env=env)
            self.assertEqual((p.returncode, out["source"]), (0, "Cert Spotter"), p.stderr)
            self.assertEqual(len(REQUESTS), 1)
            headers = REQUESTS[0][2]
            self.assertEqual(headers.get("Authorization"), want)
            self.assertEqual(headers.get("User-Agent"), UA)

    def test_webhook_post_is_json_with_tool_user_agent_and_same_document_as_exec(self):
        CRTSH["hook.test"] = [{"id": 1, "issuer_name": "C=XX, O=Odd CA", "name_value": "hook.test",
                               "not_before": ago(1), "serial_number": "01"}]
        stdin_copy = os.path.join(self.tmp, "stdin.json")
        p = run("hook.test", "--allow-issuer", "Let's Encrypt", "--webhook", BASE + "/hook",
                "--exec", "cat > " + stdin_copy)
        self.assertEqual(p.returncode, 1, p.stderr)
        posts = [r for r in REQUESTS if r[0] == "POST"]
        self.assertEqual(len(posts), 1)
        _, path, headers, body = posts[0]
        self.assertEqual((path, headers.get("Content-Type"), headers.get("User-Agent")),
                         ("/hook", "application/json", UA))
        with open(stdin_copy) as f:
            self.assertEqual(f.read(), body)  # --exec and --webhook receive the identical document
        doc = json.loads(body)
        self.assertEqual((doc["domain"], doc["source"], doc["days"]), ("hook.test", "crt.sh", 30))
        self.assertEqual([a["id"] for a in doc["alerts"]], [1])


class TestCertSpotterRecords(Base):
    def test_fields_are_mapped_and_deduped_like_crtsh(self):
        SPOTTER["cs.test"] = [[
            {"id": "1", "tbs_sha256": "AA", "dns_names": ["www.cs.test"], "not_before": ago(1) + "Z",
             "issuer": {"friendly_name": "Friendly CA"}},
            {"id": "2", "tbs_sha256": "aa", "dns_names": ["www.cs.test"], "not_before": ago(1) + "Z",
             "issuer": {"friendly_name": "Friendly CA"}},              # same TBS hash: one certificate
            {"id": "3", "cert_sha256": "bb", "dns_names": ["api.cs.test"], "not_before": ago(2) + "Z"},
            {"id": "4", "not_before": ago(3) + "Z", "issuer": {"name": LE}},
        ], [
            {"id": "5", "cert_sha256": "cc", "dns_names": ["cs.test"], "not_before": ago(4) + "Z",
             "issuer": {"name": LE, "friendly_name": "LE"}},
        ]]
        p, out = run_json("cs.test", "--source", "certspotter", "--allow-issuer", "Let's Encrypt")
        self.assertEqual(p.returncode, 1, p.stderr)
        got = {c["id"]: (c["issuer"], c["names"], c["issued"]) for c in out["certs"]}
        self.assertEqual(sorted(got), ["1", "3", "4", "5"])
        self.assertEqual(got["1"][:2], ("Friendly CA", ["www.cs.test"]))
        self.assertEqual(got["3"][:2], ("unknown", ["api.cs.test"]))
        self.assertEqual(got["4"][:2], (LE, []))
        self.assertEqual(got["5"][:2], (LE, ["cs.test"]))
        self.assertNotIn("Z", got["1"][2])
        self.assertEqual({c["id"] for c in out["certs"] if c["issuer_flagged"]}, {"1", "3"})
        pages = [parse_qs(urlparse(r[1]).query).get("after") for r in REQUESTS]
        self.assertEqual(pages, [None, ["4"], ["5"]])  # pages follow the last id until an empty page

    def test_records_without_any_hash_dedupe_by_id(self):
        SPOTTER["cs.test"] = [[{"id": "7", "dns_names": ["a.cs.test"], "not_before": ago(1) + "Z"},
                               {"id": "8", "dns_names": ["a.cs.test"], "not_before": ago(1) + "Z"}]]
        _, out = run_json("cs.test", "--source", "certspotter")
        self.assertEqual(sorted(c["id"] for c in out["certs"]), ["7", "8"])


class TestNames(Base):
    def test_trailing_dots_and_case_are_normalised(self):
        CRTSH["dot.test"] = [{"id": 1, "issuer_name": LE, "not_before": ago(1), "serial_number": "01",
                              "name_value": "WWW.dot.test.\n*.Dot.Test.\ndot.test."}]
        for arg in ("dot.test", "Dot.Test."):
            _, out = run_json(arg)
            self.assertEqual(out["domain"], "dot.test")
            self.assertEqual(out["certs"][0]["subdomains"], ["*", "@", "www"])

    def test_dedupe_key_ignores_case_and_spacing(self):
        row = {"issuer_name": LE, "name_value": "a.key.test", "not_before": ago(1)}
        CRTSH["key.test"] = [dict(row, id=1, serial_number="0AbC"),
                             dict(row, id=2, serial_number="0abc", issuer_name="  " + LE.upper() + " "),
                             dict(row, id=3, serial_number="0abd")]
        _, out = run_json("key.test")
        self.assertEqual(sorted(c["id"] for c in out["certs"]), [1, 3])

    def test_rows_without_serial_or_id_dedupe_by_names(self):
        row = {"issuer_name": LE, "not_before": ago(1)}
        CRTSH["noid.test"] = [dict(row, name_value="a.noid.test\nb.noid.test"),
                              dict(row, name_value="b.noid.test\na.noid.test"),
                              dict(row, name_value="c.noid.test")]
        _, out = run_json("noid.test")
        self.assertEqual(sorted(c["names"] for c in out["certs"]),
                         [["a.noid.test", "b.noid.test"], ["c.noid.test"]])

    def test_rows_with_unparseable_dates_are_skipped(self):
        CRTSH["date.test"] = [{"id": 1, "issuer_name": LE, "name_value": "date.test", "serial_number": "1"},
                              {"id": 2, "issuer_name": LE, "name_value": "date.test", "serial_number": "2",
                               "not_before": "yesterday"},
                              {"id": 3, "issuer_name": LE, "name_value": "date.test", "serial_number": "3",
                               "not_before": ago(1)}]
        p, out = run_json("date.test")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([c["id"] for c in out["certs"]], [3])


class TestStateFile(Base):
    def test_file_layout_and_other_domains_are_kept(self):
        state = os.path.join(self.tmp, "state.json")
        CRTSH["one.test"] = [{"id": 1, "issuer_name": LE, "name_value": "one.test", "not_before": ago(1),
                              "serial_number": "AB"}]
        CRTSH["two.test"] = [{"id": 2, "issuer_name": LE, "name_value": "two.test", "not_before": ago(1),
                              "serial_number": "CD"}]
        before = datetime.datetime.utcnow().replace(microsecond=0)
        self.assertEqual(run("one.test", "--state", state).returncode, 0)
        p, out = run_json("two.test", "--state", state)
        after = datetime.datetime.utcnow()
        self.assertEqual(out["new"], 1)  # one.test's certificates don't count for two.test
        with open(state) as f:
            raw = f.read()
        data = json.loads(raw)
        self.assertEqual(raw, json.dumps(data, indent=1, sort_keys=True))  # stable, diff-friendly file
        self.assertEqual(data["version"], 1)
        self.assertEqual(sorted(data["domains"]), ["one.test", "two.test"])
        self.assertEqual(list(data["domains"]["one.test"]), ["c=us, o=let's encrypt, cn=r11|ab"])  # issuer|serial
        first_seen = data["domains"]["two.test"]["c=us, o=let's encrypt, cn=r11|cd"]
        self.assertRegex(first_seen, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        ts = datetime.datetime.strptime(first_seen, "%Y-%m-%dT%H:%M:%SZ")
        self.assertTrue(before <= ts <= after, (before, ts, after))
        self.assertEqual(sorted(os.listdir(self.tmp)), ["state.json"])  # no temp files left behind

    def test_unreadable_state_is_exit_2_and_untouched(self):
        state = os.path.join(self.tmp, "state.json")
        with open(state, "w") as f:
            f.write("{not json")
        CRTSH["one.test"] = []
        p = run("one.test", "--state", state)
        self.assertEqual(p.returncode, 2)
        self.assertRegex(p.stderr, r"^ERROR: can't read --state %s: \S" % re.escape(state))
        with open(state) as f:
            self.assertEqual(f.read(), "{not json")

    def test_unwritable_state_is_exit_2(self):
        missing_dir = os.path.join(self.tmp, "no-such-dir", "state.json")
        CRTSH["one.test"] = []
        p = run("one.test", "--state", missing_dir)
        self.assertEqual(p.returncode, 2)
        self.assertIn("ERROR: can't write --state " + missing_dir, p.stderr)


class TestHooks(Base):
    def setUp(self):
        super().setUp()
        CRTSH["hook.test"] = [{"id": 1, "issuer_name": "C=XX, O=Odd CA", "name_value": "hook.test",
                               "not_before": ago(1), "serial_number": "01"}]

    def test_exec_inherits_environment_and_its_output_stays_out_of_the_report(self):
        mark = os.path.join(self.tmp, "mark")
        p, out = run_json("hook.test", "--allow-issuer", "Let's Encrypt",
                          "--exec", 'echo "noise on stdout"; echo "$CTW_TEST_MARK $CTW_DOMAIN $CTW_ALERTS" > ' + mark,
                          env={"CTW_TEST_MARK": "inherited"})
        self.assertEqual((p.returncode, out["flagged"]), (1, 1))
        with open(mark) as f:
            self.assertEqual(f.read().strip(), "inherited hook.test 1")
        self.assertNotIn("noise", p.stderr)

    def test_failed_exec_reports_status_and_stderr_tail(self):
        p = run("hook.test", "--allow-issuer", "Let's Encrypt", "--exec", "echo boom >&2; exit 3")
        self.assertEqual(p.returncode, 2)
        self.assertIn("ERROR: --exec command exited 3: boom (state not updated", p.stderr)
        long_err = "python3 -c \"import sys; sys.stderr.write('A' * 400 + 'END')\"; exit 4"
        p = run("hook.test", "--allow-issuer", "Let's Encrypt", "--exec", long_err)
        line = [l for l in p.stderr.splitlines() if "--exec command exited 4" in l][0]
        tail = line.split("exited 4: ", 1)[1].split(" (state not updated")[0]
        self.assertEqual(tail, "A" * 297 + "END")  # last 300 characters

    def test_failed_webhook_reports_the_http_error(self):
        HOOK_STATUS[0] = 500
        p = run("hook.test", "--allow-issuer", "Let's Encrypt", "--webhook", BASE + "/hook")
        self.assertEqual(p.returncode, 2)
        self.assertIn("ERROR: --webhook POST failed: HTTP Error 500", p.stderr)


class TestErrors(Base):
    def test_all_sources_down_names_each_failure(self):
        p = run("down.test")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr.strip(), "ERROR: could not reach crt.sh after 4 attempts: HTTP Error 502: "
                                           "Bad Gateway; Cert Spotter: HTTP Error 503: Service Unavailable")
        self.assertEqual(len(REQUESTS), 5)
        p = run("down.test", "--source", "certspotter")
        self.assertEqual(p.stderr.strip(), "ERROR: Cert Spotter: HTTP Error 503: Service Unavailable")

    def test_source_choices(self):
        CRTSH["src.test"] = []
        for src in ("auto", "crtsh"):
            p, out = run_json("src.test", "--source", src)
            self.assertEqual((p.returncode, out["source"]), (0, "crt.sh"))
        p = run("src.test", "--source", "crt.sh")
        self.assertEqual(p.returncode, 2)
        self.assertIn("invalid choice", p.stderr)

    def test_fail_on_new_without_state(self):
        p = run("src.test", "--fail-on-new")
        self.assertEqual(p.returncode, 2)
        self.assertIn("error: --fail-on-new needs --state", p.stderr)


class TestReport(Base):
    """The text report a cron mail or a terminal shows, pinned line by line."""
    def setUp(self):
        super().setUp()
        self.t = [ago(1), ago(2), ago(10)]
        CRTSH["txt.test"] = [
            {"id": 1, "issuer_name": LE, "name_value": "txt.test\nwww.txt.test", "not_before": self.t[0],
             "serial_number": "01"},
            {"id": 2, "issuer_name": "C=XX, O=Odd CA", "name_value": "staging.txt.test", "not_before": self.t[1],
             "serial_number": "02"},
            {"id": 3, "issuer_name": LE, "name_value": "*.txt.test", "not_before": self.t[2], "serial_number": "03"},
        ]

    def test_flagged_report(self):
        p = run("txt.test", "--allow-issuer", "Let's Encrypt", "--allow-subdomain", "www", "--allow-subdomain", "@")
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertEqual(p.stdout, "\n".join([
            "cert-transparency-watcher: txt.test \u2014 3 cert(s) in the last 30 day(s) (source: crt.sh)",
            "",
            "[%s] issuer=%s" % (self.t[0], LE),
            "    names: txt.test, www.txt.test",
            "[%s] issuer=C=XX, O=Odd CA" % self.t[1],
            "    names: staging.txt.test  \u26a0\ufe0f  unexpected issuer: C=XX, O=Odd CA | unexpected subdomain(s): staging",
            "[%s] issuer=%s" % (self.t[2], LE),
            "    names: *.txt.test  \u26a0\ufe0f  unexpected subdomain(s): *",
            "",
            "\u26a0\ufe0f  2 cert(s) flagged for review. Not necessarily malicious \u2014 could be a new",
            "    provider, a forgotten subdomain, or a legit CA you haven't allowlisted yet.",
            "    But worth a look: unexpected certs are the first sign of subdomain takeover",
            "    or CA-level misissuance.",
            ""]))

    def test_unflagged_report(self):
        p = run("txt.test", "--days", "5")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "\n".join([
            "cert-transparency-watcher: txt.test \u2014 2 cert(s) in the last 5 day(s) (source: crt.sh)",
            "",
            "[%s] issuer=%s" % (self.t[0], LE),
            "    names: txt.test, www.txt.test",
            "[%s] issuer=C=XX, O=Odd CA" % self.t[1],
            "    names: staging.txt.test",
            "",
            "No flags. (Note: flags only trigger if you passed --allow-issuer/--allow-subdomain \u2014",
            "without those, this just lists recent cert activity for review.)",
            ""]))

    def test_state_report(self):
        state = os.path.join(self.tmp, "state.json")
        p = run("txt.test", "--state", state, "--fail-on-new", "--allow-subdomain", "staging")
        self.assertEqual(p.returncode, 1, p.stderr)
        lines = p.stdout.splitlines()
        self.assertEqual(lines[0], "cert-transparency-watcher: txt.test \u2014 3 cert(s) new since the last run "
                                   "in the last 30 day(s) (source: crt.sh)")
        self.assertEqual([l for l in lines if l.startswith("    names:")], [
            "    names: txt.test, www.txt.test  \u26a0\ufe0f  unexpected subdomain(s): @, www",
            "    names: staging.txt.test  \u26a0\ufe0f  new certificate",
            "    names: *.txt.test  \u26a0\ufe0f  unexpected subdomain(s): *"])
        self.assertIn("\u26a0\ufe0f  3 cert(s) flagged for review.", p.stdout)
        p = run("txt.test", "--state", state, "--fail-on-new", "--allow-subdomain", "staging")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "\n".join([
            "cert-transparency-watcher: txt.test \u2014 0 cert(s) new since the last run in the last 30 day(s) "
            "(source: crt.sh)",
            "",
            "",
            "No flags. (Note: flags only trigger if you passed --allow-issuer/--allow-subdomain/--fail-on-new \u2014",
            "without those, this just lists recent cert activity for review.)",
            ""]))

    def test_already_seen_certificates_are_listed_without_markers(self):
        state = os.path.join(self.tmp, "state.json")
        run_json("txt.test", "--state", state)
        CRTSH["txt.test"].append({"id": 4, "issuer_name": LE, "name_value": "new.txt.test", "not_before": ago(0),
                                  "serial_number": "04"})
        p, out = run_json("txt.test", "--state", state, "--allow-subdomain", "www")
        self.assertEqual((p.returncode, out["flagged"], out["new"]), (1, 1, 1))
        self.assertEqual({c["id"]: (c["new"], c["flagged"], c["unexpected_subdomains"]) for c in out["certs"]},
                         {4: (True, True, ["new"]), 1: (False, False, ["@"]), 2: (False, False, ["staging"]),
                          3: (False, False, ["*"])})
        p, out = run_json("txt.test")
        self.assertEqual((out["version"], out["new"], out["days"], out["flagged"]), (VERSION, None, 30, 0))


HELP = [  # what `--help` tells a user, option by option (argparse wraps lines; compared without whitespace)
    "Monitor Certificate Transparency logs for a domain",
    "domain Domain to watch, e.g. example.com (every name under it is included)",
    "--allow-issuer ALLOW_ISSUER Substring of an issuer CA name considered expected (repeatable). "
    "If omitted, all issuers are reported without flagging.",
    "--allow-subdomain ALLOW_SUBDOMAIN Subdomain label considered expected, e.g. 'www' or 'mail' (repeatable). "
    "'@' means the bare domain, '*' a wildcard certificate for every subdomain ('*.dev' for *.dev.<domain>). "
    "If omitted, all subdomains are reported without flagging.",
    "--days DAYS Only show certs issued in the last N days (default 30)",
    "--json Emit machine-readable JSON instead of text",
    "--source {auto,crtsh,certspotter} CT data source (default: crt.sh, falling back to Cert Spotter)",
    "--state FILE remember seen certificates here; only certificates new since the last run are flagged",
    "--fail-on-new with --state: treat every new certificate as flagged, even without allow lists",
    "--exec CMD run CMD (shell) when something is flagged; the alert JSON is on stdin, "
    "CTW_DOMAIN/CTW_ALERTS in the environment",
    "--webhook URL POST the alert JSON to URL when something is flagged",
    "--crtsh-url TEMPLATE crt.sh-compatible JSON endpoint, '{}' is replaced by the query "
    "(default: https://crt.sh/?q={}&output=json) -- for a mirror or a local test server",
    "--certspotter-url URL Cert Spotter issuances endpoint (default: https://api.certspotter.com/v1/issuances; "
    "CERTSPOTTER_API_TOKEN is sent if set)",
    "Exit codes: 0 nothing flagged, 1 flagged certificates, 2 CT/hook failure or bad usage.",
]


class TestHelp(unittest.TestCase):
    def test_help_text(self):
        p = subprocess.run([sys.executable, TOOL, "--help"], stdout=subprocess.PIPE, universal_newlines=True,
                           env=dict(os.environ, COLUMNS="200"))
        self.assertEqual(p.returncode, 0)
        self.assertTrue(p.stdout.startswith("usage: cert-transparency-watcher "))
        lines = p.stdout.splitlines()
        self.assertIn(HELP[0], lines)   # description and epilog are whole lines
        self.assertIn(HELP[-1], lines)
        # everything from the positional arguments on, compared without whitespace (argparse wraps and
        # titles the options section differently across Python versions)
        body = p.stdout[p.stdout.index("positional arguments:"):]
        for title in ("positional arguments:", "optional arguments:", "options:"):
            body = body.replace(title, "", 1)
        squash = lambda s: re.sub(r"\s+", "", s)
        want = HELP[1:2] + ["-h, --help show this help message and exit",
                            "--version show program's version number and exit"] + HELP[2:]
        self.assertEqual(squash(body), squash(" ".join(want)))

    def test_defaults_are_the_public_services(self):
        """Without --crtsh-url / --certspotter-url the tool asks crt.sh and Cert Spotter themselves."""
        code = ("import sys, urllib.request; sys.path.insert(0, %r)\n"
                "import cert_transparency_watcher as c\n"
                "seen = []\n"
                "class R:\n"
                "    def __enter__(self): return self\n"
                "    def __exit__(self, *a): return False\n"
                "    def read(self): return b'[]'\n"
                "def fake(req, timeout=None):\n"
                "    seen.append((req.full_url, timeout)); return R()\n"
                "urllib.request.urlopen = fake\n"
                "rc = [c.main(['example.com', '--json', '--source', s]) for s in ('auto', 'certspotter')]\n"
                "sys.stderr.write(repr((rc, seen)))" % os.path.dirname(TOOL))
        p = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=60)
        rc, seen = eval(p.stderr)
        self.assertEqual(rc, [0, 0])
        self.assertEqual(seen, [("https://crt.sh/?q=%25.example.com&output=json", 20),
                                ("https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true"
                                 "&expand=dns_names&expand=issuer", 30)])

if __name__ == "__main__":
    unittest.main()
