"""Shared CLI contract (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, stderr for errors.

Reuses the local crt.sh / Cert Spotter / webhook fixture server of test_contract.py; the tool runs as a subprocess.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

import contract_support as cs
import test_contract as W

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import cert_transparency_watcher as tool  # noqa: E402

SCHEMA = cs.load_schema(ROOT, "cert-transparency-watcher")
DOMAIN = "contract.test"


def setUpModule():
    W.setUpModule()


def tearDownModule():
    W.tearDownModule()


def cert(issuer):
    return {"id": 1, "issuer_name": issuer, "name_value": DOMAIN, "not_before": W.ago(1), "serial_number": "01"}


class Contract(W.Base):
    def cli(self, *a):
        p = W.run(*a)
        return p.returncode, p.stdout, p.stderr

    def clean(self):
        W.CRTSH[DOMAIN] = [cert(W.LE)]
        return (DOMAIN, "--allow-issuer", "Let's Encrypt")

    def findings(self):
        W.CRTSH[DOMAIN] = [cert("C=XX, O=Odd CA")]
        return (DOMAIN, "--allow-issuer", "Let's Encrypt")


class TestExitCodes(Contract):
    def test_clean_is_0(self):
        self.assertEqual(self.cli(*self.clean())[0], 0)

    def test_findings_is_1(self):
        self.assertEqual(self.cli(*self.findings())[0], 1)

    def test_bad_args_is_2_with_message_on_stderr(self):
        for a in ((), ("--no-such-flag", DOMAIN), (DOMAIN, "--fail-on-new"), (DOMAIN, "--days", "many")):
            rc, out, err = self.cli(*a)
            self.assertEqual(rc, 2, a)
            self.assertEqual(out, "", a)
            self.assertTrue("usage:" in err or "--fail-on-new needs --state" in err, err)

    def test_unreadable_state_file_is_2(self):
        W.CRTSH[DOMAIN] = []
        bad = os.path.join(self.tmp, "state.json")
        with open(bad, "w") as f:
            f.write("not json")
        rc, out, err = self.cli(DOMAIN, "--state", bad)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("can't read --state", err)

    def test_unreachable_source_keeps_documented_legacy_code_2(self):
        rc, out, err = self.cli("nowhere.test")  # the fixture answers 502 for unknown domains
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)

    def test_unexpected_error_is_3_on_stderr_not_a_traceback_exit_1(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), redirect_stderr(buf):
            self.assertEqual(tool.main([DOMAIN]), 3)
        self.assertIn("RuntimeError: boom", buf.getvalue())


class TestJson(Contract):
    def check(self, args, code):
        rc, out, err = self.cli("--json", *args)
        self.assertEqual(rc, code, err)
        doc = json.loads(out)  # exactly one JSON document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "cert-transparency-watcher")
        self.assertEqual(doc["version"], tool.__version__)
        return doc

    def test_clean(self):
        self.assertEqual(self.check(self.clean(), 0)["flagged"], 0)

    def test_findings(self):
        doc = self.check(self.findings(), 1)
        self.assertEqual(doc["flagged"], 1)

    def test_with_state_counts_new_certificates(self):
        args = self.clean() + ("--state", os.path.join(self.tmp, "s.json"))
        self.assertEqual(self.check(args, 0)["new"], 1)
        self.assertEqual(self.check(args, 0)["new"], 0)

    def test_usage_error_leaves_stdout_empty(self):
        rc, out, err = self.cli("--json")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("usage:", err)

    def test_schema_rejects_a_document_without_the_contract_keys(self):
        self.assertNotEqual(cs.validate({"certs": []}, SCHEMA), [])
        good = {"schema_version": 1, "tool": "cert-transparency-watcher", "version": "1", "exit_code": 0,
                "domain": "d", "source": "s", "days": 30, "flagged": 0, "new": None, "certs": []}
        self.assertEqual(cs.validate(good, SCHEMA), [])
        self.assertNotEqual(cs.validate(dict(good, exit_code=9), SCHEMA), [])


class TestQuiet(Contract):
    def test_quiet_prints_nothing_but_keeps_exit_code(self):
        for setup, code in ((self.clean, 0), (self.findings, 1)):
            args = setup()
            for extra in ((), ("--json",)):
                for flag in ("--quiet", "-q"):
                    rc, out, err = self.cli(flag, *(extra + args))
                    self.assertEqual((rc, out), (code, ""), (flag, extra, args))

    def test_quiet_still_updates_state_and_runs_hooks(self):
        args = self.findings()
        state = os.path.join(self.tmp, "q.json")
        marker = os.path.join(self.tmp, "hook-ran")
        rc, out, err = self.cli("--quiet", "--state", state, "--exec", "touch " + marker, *args)
        self.assertEqual((rc, out), (1, ""))
        self.assertTrue(os.path.exists(state))
        self.assertTrue(os.path.exists(marker))

    def test_without_quiet_the_report_is_printed(self):
        self.assertIn("No flags.", self.cli(*self.clean())[1])


if __name__ == "__main__":
    unittest.main()
