import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import genesis  # noqa: E402
import server  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIX = os.path.join(ROOT, "fixtures")
T_REG = "2026-01-01T00:00:00Z"
T_AMEND = "2026-03-01T00:00:00Z"
T_NOW = "2026-06-01T00:00:00Z"
EXP = "2027-01-01T00:00:00Z"
CREATOR = genesis.sha("fixture creator C")
SPONSOR = genesis.sha("fixture sponsor S")
CONFIG = {"name": "fixture-agent", "tools": ["read", "write"],
          "temperature": 0}


def scope(**over):
    s = {"action_types": ["read", "write"],
         "counterparty_classes": ["allowlisted"],
         "resource_classes": ["fixture-data"],
         "max_value_class": "test"}
    s.update(over)
    return s


def reg_args(**over):
    fields = {"creator_ref": CREATOR, "model_ref": "model-fixture-001",
              "config": CONFIG,
              "config_hash": genesis.sha(genesis.canonical(CONFIG)),
              "purpose_scope": scope(), "expires_at": EXP,
              "now": T_REG}
    fields.update(over)
    args = dict(fields)
    args["creator_signature"] = genesis.fixture_sign_registration(
        fields)
    return args


def register(**over):
    return genesis.certificate_register(reg_args(**over))


def cert_of(out):
    return {k: out[k] for k in genesis.CERT_FIELDS}


def action(rid="a1", ts="2026-02-01T00:00:00Z", atype="read",
           cp="allowlisted", res="fixture-data", agent=None):
    return {"record_id": rid,
            "agent_ref": agent or register_agent(),
            "action_type": atype, "counterparty_class": cp,
            "resource_class": res, "ts": ts, "value_class": "test"}


_AGENT = None


def register_agent():
    global _AGENT
    if _AGENT is None:
        _AGENT = genesis._mint_agent_ref(
            CREATOR, "model-fixture-001",
            genesis.sha(genesis.canonical(CONFIG)))
    return _AGENT


def amend(cert, changes, now=T_AMEND):
    sig = genesis.fixture_sign_amendment(cert, changes, now)
    return genesis.certificate_amend(
        {"certificate_id": cert["certificate_id"], "changes": changes,
         "creator_signature": sig, "now": now})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("GENESIS_DATA_DIR")
        os.environ["GENESIS_DATA_DIR"] = self.tmp.name
        os.environ.pop("GENESIS_SURFACE", None)

    def tearDown(self):
        if self.old is None:
            os.environ.pop("GENESIS_DATA_DIR", None)
        else:
            os.environ["GENESIS_DATA_DIR"] = self.old
        self.tmp.cleanup()

    def store_bytes(self):
        p = os.path.join(self.tmp.name, "store.json")
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return f.read()


class TestHappy(Base):
    def test_f_g1_register_and_verify(self):  # F-G1
        out = register()
        self.assertEqual(out["state"], "ACTIVE")
        cert = cert_of(out)
        self.assertTrue(cert["signatures"]["creator"])
        self.assertTrue(cert["signatures"]["witness"])
        self.assertEqual(cert["value_class"], "test")
        v = genesis.certificate_verify(
            {"certificate": cert, "config": CONFIG, "now": T_NOW})
        self.assertEqual(v["verdict"], "SEAL_VALID")
        self.assertTrue(v["seal_valid"])
        self.assertEqual(v["config_body"], "presented")
        self.assertNotIn("first_failure", v)
        # witness-signed receipt, creator does not sign it
        self.assertTrue(genesis._verify_sig(
            genesis.sha(genesis.canonical(
                genesis._strip(v, ("signature",)))),
            v["signature"], genesis.WITNESS_KEY_REF))

    def test_config_not_presented_branch(self):  # Q-G4
        cert = cert_of(register())
        v = genesis.certificate_verify({"certificate": cert,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "SEAL_VALID")
        self.assertEqual(v["config_body"], "not-presented")
        bad = genesis.certificate_verify(
            {"certificate": cert, "config": {"name": "other"},
             "now": T_NOW})
        self.assertEqual(bad["verdict"], "BROKEN")
        self.assertEqual(bad["first_failure"]["step"],
                         "step3_config_binding")

    def test_fixture_files_register_and_detect(self):
        with open(os.path.join(FIX, "registration-v1.json")) as f:
            reg = json.load(f)
        with open(os.path.join(FIX, "action-in-purpose.json")) as f:
            act = json.load(f)
        out = genesis.certificate_register(reg)
        self.assertEqual(out["state"], "ACTIVE")
        run = genesis.purpose_detect(
            {"certificates": [cert_of(out)], "action_records": [act],
             "now": T_NOW})
        self.assertEqual(run["records"][0]["classification"],
                         "IN_PURPOSE")

    def test_f_g2_in_purpose_detection_recomputes(self):  # F-G2
        cert = cert_of(register())
        acts = [action("a1", atype="read"), action("a2", atype="write")]
        run = genesis.purpose_detect(
            {"certificates": [cert], "action_records": acts,
             "now": T_NOW})
        self.assertEqual([r["classification"] for r in run["records"]],
                         ["IN_PURPOSE", "IN_PURPOSE"])
        self.assertEqual(run["counts"],
                         {"IN_PURPOSE": 2, "OUT_OF_PURPOSE": 0,
                          "INDETERMINATE": 0})
        again = genesis.purpose_detect(
            {"certificates": [cert], "action_records": acts,
             "now": T_NOW})
        self.assertEqual(
            [r["detection_hash"] for r in again["records"]],
            [r["detection_hash"] for r in run["records"]])
        self.assertEqual(run["certificate_hashes_judged"],
                         [cert["record_hash"]])
        self.assertIn("$0.05", run["meter_record"]["price_shape"])

    def test_f_g3_zero_action_run(self):  # F-G3
        cert = cert_of(register())
        run = genesis.purpose_detect(
            {"certificates": [cert], "action_records": [],
             "now": T_NOW})
        self.assertEqual(run["records"], [])
        self.assertEqual(run["counts"],
                         {"IN_PURPOSE": 0, "OUT_OF_PURPOSE": 0,
                          "INDETERMINATE": 0})


class TestDetectionBattery(Base):
    def setUp(self):
        super().setUp()
        self.cert = cert_of(register())

    def detect(self, acts, certs=None):
        return genesis.purpose_detect(
            {"certificates": certs or [self.cert],
             "action_records": acts, "now": T_NOW})

    def test_f_g4_out_by_action_type(self):  # F-G4
        run = self.detect([action(atype="transact-fixture")])
        r = run["records"][0]
        self.assertEqual(r["classification"], "OUT_OF_PURPOSE")
        self.assertEqual(r["clause"], "action_types")
        self.assertNotIn("reason", r)

    def test_f_g5_out_by_counterparty_and_resource(self):  # F-G5
        run = self.detect([action("a1", cp="public"),
                           action("a2", atype="write",
                                  res="fixture-funds-test")])
        self.assertEqual(run["records"][0]["classification"],
                         "OUT_OF_PURPOSE")
        self.assertEqual(run["records"][0]["clause"],
                         "counterparty_classes")
        self.assertEqual(run["records"][1]["classification"],
                         "OUT_OF_PURPOSE")
        self.assertEqual(run["records"][1]["clause"],
                         "resource_classes")

    def test_f_g6_indeterminate_never_coerced(self):  # F-G6 / B-G6
        run = self.detect([action("a1", atype="teleport"),
                           action("a2", ts="2025-06-01T00:00:00Z")])
        r1, r2 = run["records"]
        self.assertEqual(r1["classification"], "INDETERMINATE")
        self.assertEqual(r1["reason"], "unmapped")
        self.assertEqual(r2["classification"], "INDETERMINATE")
        self.assertEqual(r2["reason"], "no-certificate-at-time")
        self.assertEqual(run["counts"],
                         {"IN_PURPOSE": 0, "OUT_OF_PURPOSE": 0,
                          "INDETERMINATE": 2})

    def test_f_g7_detection_does_not_block(self):  # F-G7 / B-G4
        act = action(atype="transact-fixture")
        before_hash = genesis.sha(genesis.canonical(act))
        before = self.store_bytes()
        run = self.detect([act])
        self.assertEqual(run["records"][0]["classification"],
                         "OUT_OF_PURPOSE")
        # action record unchanged, certificate state unchanged,
        # store bytes unchanged (detection is pure over presented
        # artifacts and writes nothing)
        self.assertEqual(genesis.sha(genesis.canonical(act)),
                         before_hash)
        self.assertEqual(self.store_bytes(), before)
        got = genesis.certificate_get(
            {"certificate_id": self.cert["certificate_id"],
             "now": T_NOW})
        self.assertEqual(got["state"], "ACTIVE")

    def test_malformed_action_refused_by_ref_others_classify(self):
        bad = {"record_id": "bad-1", "agent_ref": register_agent(),
               "action_type": "read", "ts": T_NOW,
               "value_class": "test"}  # missing classes
        run = self.detect([bad, action("ok-1")])
        self.assertEqual(run["refused_records"][0]["refusal"],
                         "ACTION_RECORD_MALFORMED")
        self.assertEqual(run["refused_records"][0]
                         ["action_record_ref"], "bad-1")
        self.assertEqual(run["records"][0]["classification"],
                         "IN_PURPOSE")
        self.assertEqual(run["counts"]["IN_PURPOSE"], 1)


class TestRegistrationRefusals(Base):
    def test_f_g8_scope_incomplete(self):  # F-G8
        s = scope()
        del s["resource_classes"]
        out = register(purpose_scope=s)
        self.assertEqual(out["refusal"], "SCOPE_INCOMPLETE")
        out = register(purpose_scope=scope(action_types=[]))
        self.assertEqual(out["refusal"], "SCOPE_INCOMPLETE")
        lst = genesis.family_list({})
        self.assertEqual(lst["count"], 0)  # no certificate exists

    def test_f_g8_scope_vocabulary_unknown(self):  # F-G8
        out = register(purpose_scope=scope(
            action_types=["read", "levitate"]))
        self.assertEqual(out["refusal"], "SCOPE_VOCABULARY_UNKNOWN")
        self.assertEqual(genesis.family_list({})["count"], 0)

    def test_f_g8_config_hash_mismatch(self):  # F-G8
        out = register(config_hash=genesis.sha("some other config"))
        self.assertEqual(out["refusal"], "CONFIG_HASH_MISMATCH")
        self.assertEqual(genesis.family_list({})["count"], 0)

    def test_herald_signature_invalid(self):
        args = reg_args()
        args["creator_signature"] = genesis.sign(
            genesis.sha("prospective"), genesis.WITNESS_KEY_REF)
        out = genesis.certificate_register(args)
        self.assertEqual(out["refusal"], "HERALD_SIGNATURE_INVALID")
        args2 = reg_args()
        args2["creator_signature"] = "0" * 64
        out = genesis.certificate_register(args2)
        self.assertEqual(out["refusal"], "HERALD_SIGNATURE_INVALID")
        self.assertEqual(genesis.family_list({})["count"], 0)

    def test_registration_metering_zero_value(self):  # spec 9.1
        register()
        m = genesis.metering_read({})
        self.assertEqual(m["count"], 1)
        rec = m["metering"][0]
        self.assertEqual(rec["event"], "genesis_registration")
        self.assertEqual(rec["amount_minor"], 0)
        self.assertEqual(rec["value_class"], "test")


class TestLifecycle(Base):
    def test_f_g9_amendment_windowed_detection(self):  # F-G9 / B-G5
        cert = cert_of(register())
        s2 = scope(action_types=["read", "write", "message"])
        out2 = amend(cert, {"purpose_scope": s2})
        self.assertEqual(out2["state"], "ACTIVE")
        cert2 = cert_of(out2)
        got = genesis.certificate_get(
            {"certificate_id": cert["certificate_id"], "now": T_NOW})
        self.assertEqual(got["state"], "SUPERSEDED")
        before = action("m1", ts="2026-02-01T00:00:00Z",
                        atype="message")
        after = action("m2", ts="2026-04-01T00:00:00Z",
                       atype="message")
        run = genesis.purpose_detect(
            {"certificates": [cert, cert2],
             "action_records": [before, after], "now": T_NOW})
        r1, r2 = run["records"]
        self.assertEqual(r1["classification"], "OUT_OF_PURPOSE")
        self.assertEqual(r1["record_hash"], cert["record_hash"])
        self.assertEqual(r1["certificate_status"], "superseded")
        self.assertEqual(r2["classification"], "IN_PURPOSE")
        self.assertEqual(r2["record_hash"], cert2["record_hash"])
        self.assertEqual(set(run["certificate_hashes_judged"]),
                         {cert["record_hash"], cert2["record_hash"]})
        v = genesis.certificate_verify(
            {"certificate": cert, "family_records": [cert2],
             "now": T_NOW})
        self.assertEqual(v["verdict"], "SUPERSEDED")
        self.assertTrue(v["seal_valid"])

    def test_f_g10_duplicate_and_stale_amendment(self):  # F-G10
        cert = cert_of(register())
        out = register()
        self.assertEqual(out["refusal"],
                         "DUPLICATE_ACTIVE_CERTIFICATE")
        cert2 = cert_of(amend(cert, {"model_ref": "model-fixture-002"}))
        stale = amend(cert, {"model_ref": "model-fixture-003"})
        self.assertEqual(stale["refusal"], "AMENDMENT_TARGET_INVALID")
        missing = genesis.certificate_amend(
            {"certificate_id": "crt_" + "0" * 16, "changes": {},
             "creator_signature": "x", "now": T_AMEND})
        self.assertEqual(missing["refusal"], "CERTIFICATE_NOT_FOUND")

    def test_f_g11_revocation(self):  # F-G11a
        cert = cert_of(register())
        t_rev = "2026-05-01T00:00:00Z"
        sig = genesis.fixture_sign_revocation(
            cert, CREATOR, t_rev, cert["record_hash"])
        out = genesis.certificate_revoke(
            {"certificate_id": cert["certificate_id"],
             "signer_ref": CREATOR, "signature": sig, "now": t_rev})
        self.assertEqual(out["state"], "REVOKED")
        stream = genesis.certificate_export(
            {"certificate_id": cert["certificate_id"]})["records"]
        v = genesis.certificate_verify(
            {"certificate": cert, "family_records": stream[1:],
             "now": T_NOW})
        self.assertEqual(v["verdict"], "REVOKED")
        self.assertTrue(v["seal_valid"])
        # pre-revocation action still recomputes, labelled revoked
        run = genesis.purpose_detect(
            {"certificates": stream,
             "action_records": [action("a1")], "now": T_NOW})
        self.assertEqual(run["records"][0]["classification"],
                         "IN_PURPOSE")
        self.assertEqual(run["records"][0]["certificate_status"],
                         "revoked")
        # unauthorized revoker refused on a fresh family
        cert_b = cert_of(register(creator_ref=genesis.sha("other")))
        out = genesis.certificate_revoke(
            {"certificate_id": cert_b["certificate_id"],
             "signer_ref": genesis.sha("stranger"), "signature": "0" * 64,
             "now": t_rev})
        self.assertEqual(out["refusal"], "HERALD_SIGNATURE_INVALID")

    def test_f_g11_expiry(self):  # F-G11b
        cert = cert_of(register(expires_at="2026-02-01T00:00:00Z"))
        v = genesis.certificate_verify({"certificate": cert,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "EXPIRED")
        self.assertTrue(v["seal_valid"])
        got = genesis.certificate_get(
            {"certificate_id": cert["certificate_id"], "now": T_NOW})
        self.assertEqual(got["state"], "EXPIRED")

    def test_sponsor_revocation(self):  # Q-G5: carried, not adjudicated
        cert = cert_of(register(sponsor_ref=SPONSOR))
        t_rev = "2026-05-01T00:00:00Z"
        sig = genesis.fixture_sign_revocation(
            cert, SPONSOR, t_rev, cert["record_hash"])
        out = genesis.certificate_revoke(
            {"certificate_id": cert["certificate_id"],
             "signer_ref": SPONSOR, "signature": sig, "now": t_rev})
        self.assertEqual(out["state"], "REVOKED")

    def test_temporal_monotonicity_at_write(self):
        cert = cert_of(register())
        out = amend(cert, {"model_ref": "model-fixture-002"},
                    now=T_REG)  # not after prior issued_at
        self.assertEqual(out["refusal"], "TEMPORAL_NON_MONOTONIC")
        got = genesis.certificate_get(
            {"certificate_id": cert["certificate_id"], "now": T_NOW})
        self.assertEqual(got["record_count"], 1)


class TestTamperDowngrade(Base):
    def setUp(self):
        super().setUp()
        self.cert = cert_of(register())

    def test_f_g12_flip_scope_value(self):  # F-G12
        bad = copy.deepcopy(self.cert)
        bad["purpose_scope"]["action_types"] = ["read", "write",
                                                "delegate"]
        v = genesis.certificate_verify({"certificate": bad,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "BROKEN")
        self.assertFalse(v["seal_valid"])
        self.assertEqual(v["first_failure"]["step"],
                         "step1_chain_recompute")
        run = genesis.purpose_detect(
            {"certificates": [bad], "action_records": [action()],
             "now": T_NOW})
        self.assertEqual(run["refusal"],
                         "DETECTION_CERTIFICATE_BROKEN")
        self.assertNotIn("records", run)  # no metering, no records

    def test_f_g12_flip_creator_ref(self):  # F-G12
        bad = copy.deepcopy(self.cert)
        bad["creator_ref"] = genesis.sha("impostor")
        v = genesis.certificate_verify({"certificate": bad,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "BROKEN")
        self.assertEqual(v["first_failure"]["step"],
                         "step1_chain_recompute")

    def test_f_g12_remove_witness_countersignature(self):  # F-G12
        bad = copy.deepcopy(self.cert)
        del bad["signatures"]["witness"]
        v = genesis.certificate_verify({"certificate": bad,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "BROKEN")
        self.assertEqual(v["first_failure"]["step"],
                         "step2_signatures")

    def test_f_g12_reorder_family_records(self):  # F-G12
        cert2 = cert_of(amend(self.cert,
                              {"model_ref": "model-fixture-002"}))
        v = genesis.certificate_verify(
            {"certificate": cert2, "family_records": [self.cert],
             "now": T_NOW})
        # stream presented out of order: linkage fails at step 1
        self.assertEqual(v["verdict"], "BROKEN")
        self.assertEqual(v["first_failure"]["step"],
                         "step1_chain_recompute")

    def test_record_supplied_key_never_read(self):
        # An extra field carrying key material is an unknown field:
        # step-1 failure by name, never a verification input.
        bad = copy.deepcopy(self.cert)
        bad["verification_key"] = "attacker-key"
        v = genesis.certificate_verify({"certificate": bad,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "BROKEN")
        self.assertIn("UNKNOWN_FIELD:verification_key",
                      v["first_failure"]["code"])
        # a certificate re-signed under the witness key as creator
        forged = copy.deepcopy(self.cert)
        forged["signatures"]["creator"] = genesis.sign(
            self.cert["record_hash"], genesis.WITNESS_KEY_REF)
        v = genesis.certificate_verify({"certificate": forged,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "BROKEN")
        self.assertEqual(v["first_failure"]["step"],
                         "step2_signatures")

    def test_f_g14_unwitnessed_import_downgrades_only(self):  # F-G14
        bad = copy.deepcopy(self.cert)
        bad["signatures"] = {"creator": self.cert["signatures"]
                             ["creator"]}
        out = genesis.certificate_export({"certificate": bad})
        self.assertEqual(out["export_label"],
                         "DOWNGRADED_CERTIFICATE_EXPORT")
        self.assertFalse(out["verified"])
        self.assertFalse(out["signed"])
        self.assertTrue(out["verdict"].startswith("BROKEN:"))
        # the genuine export still verifies, with a signed anchor
        good = genesis.certificate_export(
            {"certificate_id": self.cert["certificate_id"]})
        self.assertEqual(good["export_label"],
                         "GENESIS_CERTIFICATE_EXPORT")
        self.assertTrue(good["verified"])
        anchor = genesis.sha(good["head_hash"] + "|" +
                             str(good["record_count"]))
        self.assertTrue(genesis._verify_sig(
            anchor, good["anchor_signature"], genesis.WITNESS_KEY_REF))
        self.assertEqual(good["head_hash"],
                         self.cert["record_hash"])
        self.assertEqual(good["record_count"], 1)

    def test_tampered_store_serves_downgraded_only(self):
        store = genesis.load_store()
        fam = store["families"][self.cert["agent_ref"]]
        fam["records"][0]["purpose_scope"]["action_types"] = \
            ["read", "write", "delegate"]
        p = os.path.join(self.tmp.name, "store.json")
        with open(p, "w") as f:
            f.write(json.dumps(store, sort_keys=True))
        got = genesis.certificate_get(
            {"certificate_id": self.cert["certificate_id"],
             "now": T_NOW})
        self.assertEqual(got["export_label"],
                         "DOWNGRADED_CERTIFICATE_EXPORT")
        self.assertFalse(got["verified"])

    def test_missing_pinned_key_fails_closed(self):
        empty = os.path.join(self.tmp.name, "empty-keys.json")
        with open(empty, "w") as f:
            json.dump({}, f)
        old = genesis._key_file_path
        genesis._key_file_path = lambda: empty
        try:
            # Fail-closed: no receipt is issued at all when the
            # pinned witness key is missing (a receipt must be
            # witness-signed; an unsigned one is never emitted).
            with self.assertRaises(genesis.ToolError):
                genesis.certificate_verify(
                    {"certificate": self.cert, "now": T_NOW})
            self.assertIsNone(genesis.sign("ab" * 32,
                                           genesis.CREATOR_KEY_REF))
            # and presented-certificate signature checks fail too:
            # with keys restored this same certificate verifies.
        finally:
            genesis._key_file_path = old
        v = genesis.certificate_verify({"certificate": self.cert,
                                        "now": T_NOW})
        self.assertEqual(v["verdict"], "SEAL_VALID")


class TestDecisive(Base):
    def test_f_g13_decisive_fresh_process(self):  # F-G13 / B-G2
        cert = cert_of(register())
        agent = cert["agent_ref"]
        acts = [action("d1", atype="read", agent=agent),
                action("d2", atype="write", agent=agent),
                action("d3", atype="read", res="fixture-data",
                       agent=agent),
                action("d4", atype="transact-fixture", agent=agent),
                action("d5", atype="teleport", agent=agent)]
        exp = genesis.certificate_export(
            {"certificate_id": cert["certificate_id"]})
        payload = {"certificate": cert, "records": exp["records"],
                   "config": CONFIG, "action_records": acts,
                   "now": T_NOW}
        path = os.path.join(self.tmp.name, "decisive.json")
        with open(path, "w") as f:
            json.dump(payload, f)
        code = (
            "import json,sys;"
            "sys.path.insert(0, %r);"
            "import genesis;"
            "p=json.load(open(%r));"
            "v=genesis.certificate_verify({'certificate':"
            "p['records'][0],'config':p['config'],'now':p['now']});"
            "run=genesis.purpose_detect({'certificates':p['records'],"
            "'action_records':p['action_records'],'now':p['now']});"
            "print(json.dumps({'verdict':v['verdict'],"
            "'seal':v['seal_valid'],"
            "'classes':[r['classification'] for r in run['records']],"
            "'clauses':[r.get('clause') for r in run['records']],"
            "'reasons':[r.get('reason') for r in run['records']]}))"
            % (ROOT, path))
        env = dict(os.environ)
        fresh = os.path.join(self.tmp.name, "fresh-state")
        env["GENESIS_DATA_DIR"] = fresh
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["verdict"], "SEAL_VALID")
        self.assertTrue(out["seal"])
        self.assertEqual(out["classes"],
                         ["IN_PURPOSE", "IN_PURPOSE", "IN_PURPOSE",
                          "OUT_OF_PURPOSE", "INDETERMINATE"])
        self.assertEqual(out["clauses"],
                         [None, None, None, "action_types", None])
        self.assertEqual(out["reasons"],
                         [None, None, None, None, "unmapped"])
        # no Genesis state was needed or created by verify/detect
        self.assertFalse(os.path.exists(
            os.path.join(fresh, "store.json")))


class TestNoBlockingVerb(Base):
    FORBIDDEN_TOKENS = ("block", "suspend", "penal", "enforce",
                        "intercept", "delete", "edit", "unseal",
                        "approve", "license", "ban", "freeze")

    def test_dispatch_tables_enumerated_no_blocking_verb(self):  # B-G4
        party = set(genesis.PARTY_TOOLS)
        self.assertEqual(party, {
            "genesis_certificate_register",
            "genesis_certificate_amend",
            "genesis_certificate_revoke",
            "genesis_certificate_get",
            "genesis_certificate_verify",
            "genesis_purpose_detect",
            "genesis_certificate_export"})
        for tools in (genesis.PARTY_TOOLS, genesis.OPERATOR_TOOLS):
            for name in tools:
                for tok in self.FORBIDDEN_TOKENS:
                    self.assertNotIn(tok, name, name)
        for name in ("genesis_block", "genesis_suspend_action",
                     "genesis_enforce", "genesis_intercept",
                     "genesis_delete_certificate",
                     "genesis_edit_certificate", "genesis_unseal"):
            self.assertNotIn(name, genesis.PARTY_TOOLS)
            self.assertNotIn(name, genesis.OPERATOR_TOOLS)

    def test_surfaces_disjoint_no_oracle(self):
        os.environ["GENESIS_SURFACE"] = "party"
        nonsense = server.dispatch("genesis_nonsense", {})
        other = server.dispatch("genesis_family_list", {})
        self.assertEqual(nonsense["refusal"], "NO_SUCH_TOOL")
        self.assertEqual(nonsense["refusal"], other["refusal"])
        os.environ["GENESIS_SURFACE"] = "operator"
        other2 = server.dispatch("genesis_purpose_detect", {})
        self.assertEqual(other2["refusal"], "NO_SUCH_TOOL")


class TestMalformedBattery(Base):
    def bad_calls(self):
        cert = cert_of(register())
        return [
            ("register_empty", lambda: genesis.certificate_register(
                {})),
            ("register_bad_scope_type",
             lambda: genesis.certificate_register(
                 reg_args(purpose_scope="read"))),
            ("register_config_not_obj",
             lambda: genesis.certificate_register(
                 reg_args(config="x"))),
            ("register_long_creator",
             lambda: genesis.certificate_register(
                 reg_args(creator_ref="x" * 600))),
            ("register_bad_ts", lambda: genesis.certificate_register(
                reg_args(now="not-a-date"))),
            ("amend_missing", lambda: genesis.certificate_amend(
                {"certificate_id": cert["certificate_id"]})),
            ("amend_changes_not_obj",
             lambda: genesis.certificate_amend(
                 {"certificate_id": cert["certificate_id"],
                  "changes": [], "creator_signature": "x"})),
            ("amend_unknown_change",
             lambda: genesis.certificate_amend(
                 {"certificate_id": cert["certificate_id"],
                  "changes": {"sealed_edit": 1},
                  "creator_signature": "x", "now": T_AMEND})),
            ("revoke_bad_types", lambda: genesis.certificate_revoke(
                {"certificate_id": 5, "signer_ref": CREATOR,
                 "signature": "x"})),
            ("get_bad_type", lambda: genesis.certificate_get(
                {"certificate_id": None})),
            ("get_unknown", lambda: genesis.certificate_get(
                {"certificate_id": "crt_" + "f" * 16})),
            ("verify_extra_arg", lambda: genesis.certificate_verify(
                {"certificate": cert, "surprise": 1})),
            ("detect_not_list", lambda: genesis.purpose_detect(
                {"certificates": "x", "action_records": []})),
            ("detect_too_many", lambda: genesis.purpose_detect(
                {"certificates": [cert],
                 "action_records": [action("t%d" % i)
                                    for i in range(501)]})),
            ("export_extra", lambda: genesis.certificate_export(
                {"certificate_id": cert["certificate_id"],
                 "surprise": 1})),
            ("family_list_extra", lambda: genesis.family_list(
                {"junk": 1})),
            ("metering_extra", lambda: genesis.metering_read(
                {"junk": 1})),
        ]

    def test_malformed_args_structured_no_partial_writes(self):
        calls = self.bad_calls()  # registers the fixture family
        before = self.store_bytes()
        for name, call in calls:
            with self.assertRaises(genesis.ToolError, msg=name):
                call()
            self.assertEqual(self.store_bytes(), before, name)

    def test_unknown_argument_named_value_never_echoed(self):
        args = reg_args()
        args["zzz_unknown"] = "SECRET-VALUE-123"
        with self.assertRaises(genesis.ToolError) as cm:
            genesis.certificate_register(args)
        self.assertIn("zzz_unknown", str(cm.exception))
        self.assertNotIn("SECRET-VALUE-123", str(cm.exception))

    def test_verify_malformed_returns_broken_not_traceback(self):
        r = genesis.certificate_verify({"certificate": "nope"})
        self.assertEqual(r["verdict"], "BROKEN")
        self.assertFalse(r["seal_valid"])


class TestFenceAndCustody(Base):
    def test_key_file_custody(self):
        p = os.path.join(ROOT, "keys", "fixture-keys.json")
        self.assertEqual(oct(os.stat(p).st_mode)[-3:], "600")
        with open(os.path.join(ROOT, ".gitignore")) as f:
            self.assertIn("keys/", f.read())

    def test_fence_live_registry_env(self):
        old = os.environ.get("GENESIS_REGISTRY_URL")
        os.environ["GENESIS_REGISTRY_URL"] = "https://example.invalid/r"
        try:
            r = genesis.certificate_register(reg_args())
            self.assertEqual(r["refusal"],
                             "CONFIG_FENCE_REFUSED:live_registry")
        finally:
            if old is None:
                os.environ.pop("GENESIS_REGISTRY_URL", None)
            else:
                os.environ["GENESIS_REGISTRY_URL"] = old

    def test_fence_value_class_and_nonfixture_source(self):
        os.environ["GENESIS_VALUE_CLASS"] = "live"
        try:
            self.assertEqual(genesis.config_fence_refusal(),
                             "CONFIG_FENCE_REFUSED:value_class")
        finally:
            os.environ.pop("GENESIS_VALUE_CLASS", None)
        os.environ["GENESIS_CREATOR_SOURCE"] = "production"
        try:
            self.assertEqual(
                genesis.config_fence_refusal(),
                "CONFIG_FENCE_REFUSED:non_fixture_source")
        finally:
            os.environ.pop("GENESIS_CREATOR_SOURCE", None)

    def test_server_startup_fence(self):
        env = dict(os.environ)
        env["GENESIS_ENDPOINT"] = "https://example.invalid/x"
        proc = subprocess.run([sys.executable,
                               os.path.join(ROOT, "server.py")],
                              input="", capture_output=True, text=True,
                              env=env)
        self.assertIn("CONFIG_FENCE_REFUSED:non_local_endpoint",
                      proc.stderr + proc.stdout)

    def test_no_network_imports_tree_wide(self):  # F-G14 grep
        import re as _re
        bad = ("sock" + "et", "url" + "lib", "requ" + "ests",
               "htt" + "px")
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames
                           if d != "__pycache__"]
            for name in filenames:
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(dirpath, name)) as f:
                    text = f.read()
                for mod in bad:
                    self.assertIsNone(_re.search(
                        r"^\s*(?:import|from)\s+" + mod + r"\b",
                        text, _re.M), "%s in %s" % (mod, name))

    def test_stdio_roundtrip_and_crash_proof(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "genesis_certificate_verify",
                        "arguments": {"certificate": "garbage"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "genesis_certificate_register",
                        "arguments": reg_args()}},
            {"jsonrpc": "2.0", "id": 5, "method": "bogus/method"},
        ]
        lines_in = ["this is not json"] + \
            [json.dumps(r) for r in reqs]
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "server.py")],
            input="\n".join(lines_in), capture_output=True,
            text=True, env=dict(os.environ))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [json.loads(x) for x in proc.stdout.strip().split("\n")]
        self.assertEqual(len(lines), 5)  # garbage line skipped, alive
        tools = [t["name"] for t in lines[1]["result"]["tools"]]
        self.assertIn("genesis_purpose_detect", tools)
        self.assertNotIn("genesis_family_list", tools)
        broken = json.loads(lines[2]["result"]["content"][0]["text"])
        self.assertEqual(broken["verdict"], "BROKEN")
        payload = json.loads(lines[3]["result"]["content"][0]["text"])
        self.assertEqual(payload["state"], "ACTIVE")
        self.assertEqual(payload["value_class"], "test")


class TestLabelsAndText(Base):
    def test_purpose_text_unsealed_only(self):  # spec 11.4
        out = register(purpose_text="reads fixture data for audits")
        cert = cert_of(out)
        self.assertNotIn("purpose_text", cert)
        self.assertNotIn("reads fixture data",
                         genesis.canonical(cert))
        got = genesis.certificate_get(
            {"certificate_id": cert["certificate_id"], "now": T_NOW})
        self.assertEqual(got["unsealed_summary"]["label"],
                         "unsealed_summary")
        self.assertEqual(got["unsealed_summary"]["purpose_text"],
                         "reads fixture data for audits")
        exp = genesis.certificate_export(
            {"certificate_id": cert["certificate_id"]})
        self.assertEqual(exp["unsealed_summaries"]
                         [cert["certificate_id"]]["label"],
                         "unsealed_summary")

    def test_honest_labels_in_readme(self):
        with open(os.path.join(ROOT, "README.md")) as f:
            readme = f.read()
        self.assertIn("PASS-CONDITIONAL(local/fixture)",
                      readme)
        self.assertIn("external anchor required before "
                      "live/multi-party use", readme)
        self.assertIn("detects, it never blocks", readme)
        self.assertIn("HMAC fixture stand-in for Herald RS256",
                      readme)


if __name__ == "__main__":
    unittest.main()
