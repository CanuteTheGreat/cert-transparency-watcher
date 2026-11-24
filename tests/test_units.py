"""Function-level behaviour of the tool, called in-process (found as mutation-testing survivors):
the exact arguments handed to urllib / tempfile / subprocess, the retry schedule, how Cert Spotter rows
are mapped, the --state file layout, hook payloads and error texts, and main() with an explicit argv,
fixed clocks and injected CT rows. Nothing here touches the network.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import cert_transparency_watcher as tool  # noqa: E402

UA = "cert-transparency-watcher/%s (+https://errant.solutions)" % tool.__version__
LE = "C=US, O=Let's Encrypt, CN=R11"
NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)


class FakeResp(object):
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.body


class FakeDateTime(datetime):
    """datetime whose now() is fixed: UTC when asked for a timezone, +10 h local time otherwise."""

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return (NOW + timedelta(hours=10)).replace(tzinfo=None)
        return NOW.astimezone(tz)


def run_main(argv, entries=None, **patches):
    """tool.main(argv) with fetch_certs returning `entries`; returns (code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        with mock.patch.object(tool, "fetch_certs", return_value=(entries or [], "crt.sh")):
            with mock.patch.multiple(tool, **patches) if patches else contextlib.suppress():
                code = tool.main(argv)
    return code, out.getvalue(), err.getvalue()


def row(i, not_before="2026-03-09T00:00:00", issuer=LE, names="www.example.com", **extra):
    d = {"id": i, "not_before": not_before, "issuer_name": issuer, "name_value": names}
    d.update(extra)
    return d


class GetTests(unittest.TestCase):
    def call(self, body=b"ok", **kw):
        with mock.patch.object(tool.urllib.request, "urlopen", return_value=FakeResp(body)) as m:
            res = tool._get("http://x.test/p", 7, **kw)
        return res, m

    def test_timeout_and_user_agent_are_passed_on(self):
        res, m = self.call()
        self.assertEqual(res, "ok")
        req = m.call_args[0][0]
        self.assertEqual(req.full_url, "http://x.test/p")
        self.assertEqual(req.get_header("User-agent"), UA)
        self.assertEqual(m.call_args[1], {"timeout": 7})

    def test_extra_headers_are_sent_next_to_the_user_agent(self):
        _, m = self.call(headers={"X-Thing": "1"})
        req = m.call_args[0][0]
        self.assertEqual(req.get_header("X-thing"), "1")
        self.assertEqual(req.get_header("User-agent"), UA)

    def test_invalid_utf8_is_replaced_not_raised(self):
        res, _ = self.call(b"a\xffb")
        self.assertEqual(res, u"a\ufffdb")


class FetchCrtshTests(unittest.TestCase):
    def test_defaults_timeout_20_and_four_attempts(self):
        calls, sleeps = [], []

        def fake_get(url, timeout):
            calls.append(timeout)
            raise urllib.error.URLError("down")

        with mock.patch.object(tool, "_get", fake_get):
            with self.assertRaises(tool.FetchError) as cm:
                tool.fetch_crtsh("example.com", sleep=sleeps.append)
        self.assertEqual(calls, [20, 20, 20, 20])
        self.assertEqual(sleeps, [2, 4, 6])  # linear back-off, none after the last attempt
        self.assertEqual(str(cm.exception), "could not reach crt.sh after 4 attempts: <urlopen error down>")

    def test_no_sleep_after_the_only_attempt(self):
        sleeps = []
        with mock.patch.object(tool, "_get", side_effect=OSError("reset")):
            with self.assertRaises(tool.FetchError):
                tool.fetch_crtsh("example.com", retries=1, sleep=sleeps.append)
        self.assertEqual(sleeps, [])

    def test_empty_body_is_retried_then_means_no_certs(self):
        sleeps = []
        with mock.patch.object(tool, "_get", return_value="  \n") as g:
            self.assertEqual(tool.fetch_crtsh("example.com", retries=3, sleep=sleeps.append), [])
        self.assertEqual(g.call_count, 3)
        self.assertEqual(sleeps, [2, 4])

    def test_unparseable_response_error_text(self):
        with mock.patch.object(tool, "_get", return_value="<html>nope"):
            with self.assertRaises(tool.FetchError) as cm:
                tool.fetch_crtsh("example.com", sleep=lambda s: None)
        self.assertEqual(str(cm.exception), "could not parse crt.sh response")


class FetchCertspotterTests(unittest.TestCase):
    def fetch(self, rows, token=None, **kw):
        env = {k: v for k, v in os.environ.items() if k != "CERTSPOTTER_API_TOKEN"}
        if token:
            env["CERTSPOTTER_API_TOKEN"] = token
        seen = []

        def fake_get(url, timeout, headers=None):
            seen.append((url, timeout, headers))
            return json.dumps(rows if len(seen) == 1 else [])

        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(tool, "_get", fake_get):
            return tool.fetch_certspotter("example.com", "http://cs.test/i", **kw), seen

    def test_token_header_and_default_timeout(self):
        _, seen = self.fetch([{"id": "1"}], token="tok")
        self.assertEqual(seen[0][1], 30)
        self.assertEqual(seen[0][2], {"Authorization": "Bearer tok"})
        _, seen = self.fetch([{"id": "1"}])
        self.assertEqual(seen[0][2], {})

    def test_stops_after_max_pages_by_default(self):
        n = []

        def endless(url, timeout, headers=None):
            n.append(url)
            return json.dumps([{"id": str(len(n))}])

        with mock.patch.object(tool, "_get", endless):
            out = tool.fetch_certspotter("example.com", "http://cs.test/i")
        self.assertEqual(len(n), 20)
        self.assertEqual(len(out), 20)

    def test_row_mapping(self):
        out, _ = self.fetch([{"id": "7", "dns_names": ["a.example.com", "b.example.com"], "issuer": {"name": "N"},
                              "not_before": "2026-03-01T01:02:03Z", "tbs_sha256": "T", "cert_sha256": "C"}])
        self.assertEqual(out, [{"id": "7", "issuer_name": "N", "name_value": "a.example.com\nb.example.com",
                                "not_before": "2026-03-01T01:02:03", "serial_number": "T"}])

    def test_missing_fields_get_neutral_values(self):
        out, _ = self.fetch([{"id": "7"}])
        self.assertEqual(out, [{"id": "7", "issuer_name": "unknown", "name_value": "",
                                "not_before": "", "serial_number": "7"}])

    def test_serial_falls_back_from_tbs_to_cert_sha_to_id(self):
        out, _ = self.fetch([{"id": "1", "cert_sha256": "C"}, {"id": "2", "tbs_sha256": "T", "cert_sha256": "C"},
                             {"id": "3"}, {"id": "4", "cert_sha256": "C4"}])
        self.assertEqual([o["serial_number"] for o in out], ["C", "T", "3", "C4"])


class SmallHelperTests(unittest.TestCase):
    def test_cert_key_falls_back_to_the_sorted_names(self):
        self.assertEqual(tool.cert_key(" Issuer ", None, {"b.x", "a.x"}), "issuer|a.x,b.x")
        self.assertEqual(tool.cert_key("I", "AB12", {"a.x"}), "i|ab12")

    def test_cloudflare_hint_is_silent_when_the_preset_is_in_use(self):
        args = mock.Mock(allow_issuer_preset=["cloudflare"], allow_issuer=["Cloudflare"])
        alerts = [{"issuer": "C=US, O=Google Trust Services, CN=WE1", "issuer_flagged": True}]
        self.assertEqual(tool.cloudflare_hint(args, alerts), [])
        args = mock.Mock(allow_issuer_preset=[], allow_issuer=["Cloudflare"])
        self.assertEqual(tool.cloudflare_hint(args, alerts), ["C=US, O=Google Trust Services, CN=WE1"])
        args = mock.Mock(allow_issuer_preset=["CLOUDFLARE"], allow_issuer=["Cloudflare"])
        self.assertEqual(tool.cloudflare_hint(args, alerts), ["C=US, O=Google Trust Services, CN=WE1"])


class StateFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "state.json")

    def test_load_state_unknown_domain_is_an_empty_dict(self):
        with open(self.path, "w") as f:
            json.dump({"domains": {"a.test": {"k": "t"}}}, f)
        self.assertEqual(tool.load_state(self.path, "other.test"), {})
        self.assertEqual(tool.load_state(self.path, "a.test"), {"k": "t"})
        self.assertEqual(tool.load_state(os.path.join(self.dir, "none.json"), "a.test"), {})

    def test_load_state_error_names_the_file_and_the_cause(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        with self.assertRaises(tool.FetchError) as cm:
            tool.load_state(self.path, "a.test")
        msg = str(cm.exception)
        self.assertTrue(msg.startswith("can't read --state %s: " % self.path), msg)
        self.assertNotIn("None", msg)
        self.assertIn("line 1 column", msg)

    def test_save_state_layout_is_sorted_and_indented(self):
        tool.save_state(self.path, "b.test", {"z": "1", "a": "2"})
        tool.save_state(self.path, "a.test", {"y": "3", "b": "4"})
        with open(self.path) as f:
            text = f.read()
        expected = json.dumps({"domains": {"a.test": {"y": "3", "b": "4"}, "b.test": {"z": "1", "a": "2"}},
                               "version": 1}, indent=1, sort_keys=True)
        self.assertEqual(text, expected)
        self.assertEqual(sorted(os.listdir(self.dir)), ["state.json"])  # no temp file left behind

    def test_save_state_stages_next_to_the_target_with_the_ct_state_prefix(self):
        real = tempfile.mkstemp
        with mock.patch.object(tool.tempfile, "mkstemp", side_effect=real) as m:
            tool.save_state(os.path.join(self.dir, ".", "state.json"), "a.test", {})
        self.assertEqual(m.call_args[1], {"dir": os.path.abspath(self.dir), "prefix": ".ct-state-"})


class RunHooksTests(unittest.TestCase):
    def args(self, **kw):
        d = dict(exec_cmd=None, webhook=None)
        d.update(kw)
        return mock.Mock(**d)

    payload = {"domain": "example.com", "source": "crt.sh", "days": 30, "alerts": [{"id": 1}]}

    def test_exec_gets_the_indented_payload_on_stdin(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        out = os.path.join(d, "stdin.txt")
        tool.run_hooks(self.args(exec_cmd="cat > %s" % out), self.payload)
        with open(out) as f:
            self.assertEqual(f.read(), json.dumps(self.payload, indent=2))

    def test_exec_stdout_is_captured_not_passed_through(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        cap = os.path.join(d, "out.txt")
        fd = os.open(cap, os.O_WRONLY | os.O_CREAT)
        saved = os.dup(1)
        try:
            os.dup2(fd, 1)
            tool.run_hooks(self.args(exec_cmd="echo leaked-to-our-stdout"), self.payload)
        finally:
            os.dup2(saved, 1)
            os.close(saved)
            os.close(fd)
        with open(cap) as f:
            self.assertEqual(f.read(), "")

    def test_webhook_request_and_timeout(self):
        with mock.patch.object(tool.urllib.request, "urlopen", return_value=FakeResp(b"")) as m:
            tool.run_hooks(self.args(webhook="http://hook.test/x"), self.payload)
        req = m.call_args[0][0]
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.data, json.dumps(self.payload, indent=2).encode())
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(req.get_header("User-agent"), UA)
        self.assertEqual(m.call_args[1], {"timeout": 30})

    def test_failing_exec_reports_code_and_stderr_tail(self):
        with self.assertRaises(tool.FetchError) as cm:
            tool.run_hooks(self.args(exec_cmd="echo boom >&2; exit 3"), self.payload)
        self.assertEqual(str(cm.exception), "--exec command exited 3: boom")

    def test_failing_webhook_error_text(self):
        with mock.patch.object(tool.urllib.request, "urlopen", side_effect=urllib.error.URLError("refused")):
            with self.assertRaises(tool.FetchError) as cm:
                tool.run_hooks(self.args(webhook="http://hook.test/x"), self.payload)
        self.assertEqual(str(cm.exception), "--webhook POST failed: <urlopen error refused>")


class MainTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)
        self.state = os.path.join(self.dir, "state.json")

    def test_explicit_argv_wins_over_sys_argv(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["prog", "--bogus-option"]), contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as cm:
                tool.main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), "cert-transparency-watcher " + tool.__version__)

    def test_unexpected_exception_is_exit_3_with_one_stderr_line(self):
        err = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), contextlib.redirect_stderr(err):
            self.assertEqual(tool.main([]), 3)
        self.assertEqual(err.getvalue(), "cert-transparency-watcher: error: RuntimeError: boom\n")

    def test_state_records_first_seen_in_utc_not_local_time(self):
        code, _, _ = run_main(["example.com", "--state", self.state], [row(1)], datetime=FakeDateTime)
        self.assertEqual(code, 0)
        with open(self.state) as f:
            seen = json.load(f)["domains"]["example.com"]
        self.assertEqual(list(seen.values()), ["2026-03-10T12:00:00Z"])

    def test_cert_issued_exactly_at_the_cutoff_is_still_in_the_window(self):
        code, out, _ = run_main(["example.com", "--days", "1", "--json"],
                                [row(1, not_before="2026-03-09T12:00:00"), row(2, not_before="2026-03-09T11:59:59")],
                                datetime=FakeDateTime)
        self.assertEqual([c["id"] for c in json.loads(out)["certs"]], [1])

    def test_not_before_is_read_up_to_the_seconds_only(self):
        _, out, _ = run_main(["example.com", "--json"],
                             [row(1, not_before="2026-03-09T00:00:00Z"),
                              row(2, not_before="2026-03-08T00:00:00.123456")], datetime=FakeDateTime)
        self.assertEqual([c["id"] for c in json.loads(out)["certs"]], [1, 2])

    def test_missing_issuer_reads_unknown(self):
        e = row(1)
        del e["issuer_name"]
        _, out, _ = run_main(["example.com", "--json"], [e], datetime=FakeDateTime)
        self.assertEqual(json.loads(out)["certs"][0]["issuer"], "unknown")

    def test_rows_without_serial_are_told_apart_by_id(self):
        _, out, _ = run_main(["example.com", "--json"], [row(1), row(2), row(2)], datetime=FakeDateTime)
        self.assertEqual(sorted(c["id"] for c in json.loads(out)["certs"]), [1, 2])

    def test_json_output_is_indented_by_two_in_a_fixed_key_order(self):
        _, out, _ = run_main(["example.com", "--json"], [row(1)], datetime=FakeDateTime)
        expected = {"schema_version": 1, "tool": "cert-transparency-watcher", "version": tool.__version__,
                    "exit_code": 0, "domain": "example.com", "source": "crt.sh", "days": 30, "flagged": 0,
                    "new": None,
                    "certs": [{"id": 1, "issued": "2026-03-09T00:00:00", "issuer": LE, "names": ["www.example.com"],
                               "subdomains": ["www"], "issuer_flagged": False, "unexpected_subdomains": [],
                               "new": True, "flagged": False}]}
        self.assertEqual(out, json.dumps(expected, indent=2) + "\n")

    def test_failed_hook_is_exit_2_and_says_state_was_not_updated(self):
        code, _, err = run_main(["example.com", "--allow-issuer", "Nobody", "--exec", "echo bad >&2; exit 5",
                                 "--state", self.state], [row(1)], datetime=FakeDateTime)
        self.assertEqual(code, 2)
        self.assertEqual(err, "ERROR: --exec command exited 5: bad (state not updated, so the next run alerts again)\n")
        self.assertFalse(os.path.exists(self.state))

    def test_unwritable_state_is_exit_2_with_the_cause(self):
        code, _, err = run_main(["example.com", "--state", self.state], [row(1)], datetime=FakeDateTime,
                                save_state=mock.Mock(side_effect=OSError("disk full")))
        self.assertEqual(code, 2)
        self.assertEqual(err, "ERROR: can't write --state %s: disk full\n" % self.state)


if __name__ == "__main__":
    unittest.main()
