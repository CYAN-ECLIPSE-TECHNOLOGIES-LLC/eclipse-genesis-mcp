#!/usr/bin/env python3
# Eclipse Genesis core. Copyright 2026 Cyan Eclipse Technologies LLC.
"""Agent birth-certificate issuer + out-of-purpose detector
(spec SPEC.md).

LOCAL ONLY, fixture agents/creators/keys only. At registration the
creator, model, config hash, and declared purpose scope are sealed
into a Herald-signed, hash-chained certificate; any holder can
recompute the seal offline, and witnessed action records (Docket /
Meter grammar, consumed by reference only) can be classified against
the sealed scope. Genesis DETECTS, it never blocks (L3): no verb in
this tree intercepts, prevents, suspends, or penalises an action or
an agent, and detection mutates neither action records nor
certificate state.

Signing: HMAC-SHA256 fixture keys standing in for Herald RS256
(house pattern, disclosed on every face). Verification keys are
PINNED out-of-band by fixed key ref ("creator-fixture" /
"witness-fixture" / "sponsor-fixture") loaded from the local
chmod-600 gitignored key file - a key or key ref is NEVER accepted
from the record under verification. Every verify path RECOMPUTES
hashes from source data; presented/stored digests are claims, never
trusted. Counter-signatures are cryptographically verified on every
path. State (ACTIVE / SUPERSEDED / REVOKED / EXPIRED) is DERIVED
from the signed record stream only; indexes are rebuilt, never
stored as truth. All artifacts value_class "test".

COUNSEL GATE (spec 10, named, unbuilt): any live phase - a real
registry accepting real registrations, certificates presented to
third parties for reliance, detection records used in disputes,
enforcement, or platform decisions - requires counsel review BEFORE
build. No live registry path, no network fetch, and no enforcement
code exists in this tree; a live phase is a separate counsel-cleared,
re-benched build, not a configuration change.
"""
import hashlib
import hmac
import json
import os
import re
from datetime import datetime

PRODUCT = "eclipse-genesis"
TOOL_VERSION = "0.1.0"
SCOPE = "local, fixture agents"
VALUE_CLASS = "test"
DEFAULT_NOW = "2026-10-27T00:00:00Z"
DEFAULT_EXPIRES = "2027-10-27T00:00:00Z"
SIGNER_LABEL = "herald-fixture (fixture HMAC stand-in)"
CREATOR_KEY_REF = "creator-fixture"    # pinned out-of-band
WITNESS_KEY_REF = "witness-fixture"    # pinned out-of-band
SPONSOR_KEY_REF = "sponsor-fixture"    # pinned out-of-band
DETECTOR_METHODOLOGY_VERSION = "genesis-detector-0.1.0"
PRICE_SHAPE_REGISTER = "FREE (zero-value metering record)"
PRICE_SHAPE_VERIFY = "$0.05/verification (metering point only, " \
                     "no charge path)"
MAX_STR = 512
MAX_ACTIONS = 500
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

ACTION_TYPES = ("read", "write", "transact-fixture", "message",
                "delegate")
COUNTERPARTY_CLASSES = ("public", "allowlisted", "auditor")
RESOURCE_CLASSES = ("fixture-data", "fixture-compute",
                    "fixture-funds-test")
SCOPE_FIELDS = {"action_types", "counterparty_classes",
                "resource_classes", "max_value_class"}
CERT_FIELDS = {"certificate_id", "record_type", "agent_ref",
               "creator_ref", "model_ref", "config_hash",
               "purpose_scope", "issued_at", "expires_at",
               "supersedes", "sponsor_ref", "prev_hash",
               "record_hash", "signatures", "value_class"}
REV_FIELDS = {"record_type", "certificate_id", "agent_ref",
              "signer_ref", "ts", "prev_hash", "record_hash",
              "signatures", "value_class"}
ACTION_FIELDS = {"record_id", "agent_ref", "action_type",
                 "counterparty_class", "resource_class", "ts",
                 "value_class"}
REFUSAL_CODES = {"CERTIFICATE_NOT_FOUND",
                 "DUPLICATE_ACTIVE_CERTIFICATE", "SCOPE_INCOMPLETE",
                 "SCOPE_VOCABULARY_UNKNOWN", "CONFIG_HASH_MISMATCH",
                 "HERALD_SIGNATURE_INVALID",
                 "AMENDMENT_TARGET_INVALID", "ACTION_RECORD_MALFORMED",
                 "DETECTION_CERTIFICATE_BROKEN"}


class ToolError(Exception):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _valid_ts(v):
    if not isinstance(v, str) or not TS_RE.match(v):
        return False
    try:
        datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _strip(rec, drop):
    return {k: v for k, v in rec.items() if k not in drop}


# ---------- fixture key custody (spec 7.4) ----------

def _key_file_path():
    return os.environ.get(
        "GENESIS_FIXTURE_KEY_FILE",
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "keys", "fixture-keys.json"))


def _load_keys():
    try:
        with open(_key_file_path(), encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def sign(payload_hash, key_ref):
    key = _load_keys().get(key_ref)
    if not isinstance(key, str):
        return None
    return hmac.new(key.encode(), payload_hash.encode(),
                    hashlib.sha256).hexdigest()


def _verify_sig(payload_hash, signature, key_ref):
    # Fail-closed: a missing pinned key verifies nothing.
    expected = sign(payload_hash, key_ref)
    return expected is not None and isinstance(signature, str) and \
        hmac.compare_digest(expected, signature)


# ---------- fail-closed config fence (spec 7.3) ----------

def _frag(*parts):
    return "".join(parts)


def _endpoint_host(val):
    s = (val or "").strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    elif s.startswith("//"):
        s = s[2:]
    authority = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        end = authority.find("]")
        host = authority[1:end] if end > 0 else authority
    else:
        host = authority.split(":")[0]
    return host.rstrip(".")


def _endpoint_is_local(val):
    if (val or "").strip().lower() == "stdio":
        return True
    host = _endpoint_host(val)
    return host in ("localhost", "127.0.0.1", "::1") or \
        host.endswith(".localhost")


def config_fence_refusal():
    """Return "CONFIG_FENCE_REFUSED:<class>" or None (spec 7.3).

    Classes: live_key, live_registry, non_local_endpoint,
    non_fixture_source, value_class, key_custody, payment_module.
    Forbidden literals assembled from fragments so the fence does
    not trip its own scan.
    """
    live_marks = (_frag("sk_", "live_"), _frag("pk_", "live_"),
                  _frag("rk_", "live_"))
    exec_marks = (_frag("PAY", "MENT"), _frag("BILL", "ING"),
                  _frag("CHAR", "GE"), _frag("CHECK", "OUT"))
    exec_tokens = set(exec_marks)
    root = os.path.dirname(os.path.abspath(__file__))
    keys_dir = os.path.join(root, "keys")
    for name, val in sorted(os.environ.items()):
        val = val or ""
        upper = name.upper()
        tokens = set(re.split(r"[^A-Z0-9]+", upper))
        if val and any(m in val for m in live_marks):
            return "CONFIG_FENCE_REFUSED:live_key"
        if val and "LIVE" in tokens and \
                tokens & {"KEY", "SECRET", "TOKEN"}:
            return "CONFIG_FENCE_REFUSED:live_key"
        if upper.endswith("VALUE_CLASS") and val != VALUE_CLASS:
            return "CONFIG_FENCE_REFUSED:value_class"
        if "REGISTRY" in tokens and val and \
                not _endpoint_is_local(val) and \
                val.lower() not in ("", "none", "absent", "local"):
            return "CONFIG_FENCE_REFUSED:live_registry"
        if tokens & {"ENDPOINT", "URL", "HOST"} and val and \
                not _endpoint_is_local(val):
            return "CONFIG_FENCE_REFUSED:non_local_endpoint"
        if name == "GENESIS_FIXTURE_KEY_FILE" and val:
            if os.path.dirname(os.path.abspath(val)) != keys_dir:
                return "CONFIG_FENCE_REFUSED:key_custody"
        if name.startswith("GENESIS_"):
            if tokens & {"CREATOR_SOURCE", "AGENT_SOURCE",
                         "SOURCE"} and \
                    val not in ("", "fixture", "fixtures", "local"):
                return "CONFIG_FENCE_REFUSED:non_fixture_source"
            if tokens & exec_tokens and \
                    val.lower() not in ("", "none", "absent", "0"):
                return "CONFIG_FENCE_REFUSED:payment_module"
    # Tree scan (recursive): no network or funds-movement module may
    # be imported by any python file in the tree (7.3: absence is
    # greppable, not merely unused).
    net_mods = (_frag("sock", "et"), _frag("url", "lib"),
                _frag("requ", "ests"), _frag("htt", "px"))
    pay_mods = (_frag("stri", "pe"), _frag("pay", "pal"))
    bad_names = (_frag("wal", "let"), _frag("check", "out"),
                 _frag("pay", "ment"), _frag("bill", "ing"),
                 _frag("char", "ge"))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in filenames:
            low = name.lower()
            if not low.endswith(".py"):
                continue
            if any(t in low for t in bad_names):
                return "CONFIG_FENCE_REFUSED:payment_module"
            try:
                with open(os.path.join(dirpath, name),
                          encoding="utf-8") as f:
                    text = f.read()
            except OSError:
                continue
            for mod in net_mods + pay_mods:
                if re.search(r"^\s*(?:import|from)\s+" +
                             re.escape(mod) + r"\b", text, re.M):
                    cls = "payment_module" if mod in pay_mods else \
                        "non_local_endpoint"
                    return "CONFIG_FENCE_REFUSED:" + cls
    return None


def _fence_result():
    fence = config_fence_refusal()
    if fence is None:
        return None
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "refusal": fence, "detail": "",
            "value_class": VALUE_CLASS}


def _refusal(code, detail=""):
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "refusal": code, "detail": detail,
            "value_class": VALUE_CLASS}


# ---------- argument validation (malformed-args battery) ----------
# Wrong-type / missing / oversized arguments raise ToolError before
# any state is touched: structured error, no traceback, no partial
# writes. Unknown argument names are refused BY NAME; their values
# are never echoed.

def _req_obj(args, name):
    v = args.get(name)
    if not isinstance(v, dict):
        raise ToolError("argument must be an object: %s" % name)
    return v


def _req_str(args, name, required=True):
    v = args.get(name)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v or len(v) > MAX_STR:
        raise ToolError("argument must be a non-empty string "
                        "(<= %d chars): %s" % (MAX_STR, name))
    return v


def _req_list(args, name):
    v = args.get(name)
    if not isinstance(v, list):
        raise ToolError("argument must be an array: %s" % name)
    return v


def _check_no_extra(args, allowed):
    extra = set(args) - set(allowed)
    if extra:
        raise ToolError("unexpected arguments: %s"
                        % ",".join(sorted(extra)))


def _now_arg(args):
    now = args.get("now") or DEFAULT_NOW
    if not _valid_ts(now):
        raise ToolError("now must be an ISO timestamp")
    return now


# ---------- certificate construction (spec 4.1 / 4.2) ----------

def _seed_hash(agent_ref):
    # The stream anchor: the first certificate's prev_hash.
    return sha("eclipse-genesis/register" + agent_ref)


def _mint_agent_ref(creator_ref, model_ref, config_hash):
    return "agt_" + sha("eclipse-genesis/agent|" + creator_ref + "|" +
                        model_ref + "|" + config_hash)[:16]


def _reg_fields(fields):
    """Normalize registration-shaped fields (tool args or fixture
    helper input) into the sealed declaration set."""
    config_hash = fields.get("config_hash")
    if config_hash is None and isinstance(fields.get("config"), dict):
        config_hash = sha(canonical(fields["config"]))
    return {"creator_ref": fields.get("creator_ref"),
            "model_ref": fields.get("model_ref"),
            "config_hash": config_hash,
            "purpose_scope": fields.get("purpose_scope"),
            "sponsor_ref": fields.get("sponsor_ref") or "absent",
            "expires_at": fields.get("expires_at") or
            DEFAULT_EXPIRES,
            "issued_at": fields.get("issued_at") or
            fields.get("now") or DEFAULT_NOW}


def _cert_base(reg, agent_ref, supersedes, prev_hash):
    return {"record_type": "genesis_certificate",
            "agent_ref": agent_ref,
            "creator_ref": reg["creator_ref"],
            "model_ref": reg["model_ref"],
            "config_hash": reg["config_hash"],
            "purpose_scope": reg["purpose_scope"],
            "issued_at": reg["issued_at"],
            "expires_at": reg["expires_at"],
            "supersedes": supersedes,
            "sponsor_ref": reg["sponsor_ref"],
            "prev_hash": prev_hash,
            "value_class": VALUE_CLASS}


def _certificate_id(base):
    return "crt_" + sha(canonical(base))[:16]


def _record_hash(rec):
    # Spec 4.1: sha256(canonical(record minus hash/signature
    # fields) || prev_hash).
    return sha(canonical(_strip(rec, ("record_hash", "signatures"))) +
               "|" + rec["prev_hash"])


def _finalize_cert(base, creator_signature):
    rec = dict(base)
    rec["certificate_id"] = _certificate_id(base)
    rec["record_hash"] = _record_hash(rec)
    witness = sign(rec["record_hash"], WITNESS_KEY_REF)
    if witness is None:
        raise ToolError("witness fixture key unavailable")
    rec["signatures"] = {"creator": creator_signature,
                         "witness": witness}
    return rec


def fixture_sign_registration(fields):
    """Fixture helper: the creator (Herald) signature over a
    registration presentation, computed exactly as the register tool
    will recompute it."""
    reg = _reg_fields(fields)
    agent = _mint_agent_ref(reg["creator_ref"], reg["model_ref"],
                            reg["config_hash"])
    base = _cert_base(reg, agent, None, _seed_hash(agent))
    probe = dict(base)
    probe["certificate_id"] = _certificate_id(base)
    return sign(_record_hash(probe), CREATOR_KEY_REF)


def _amend_reg(prior, changes, now):
    config_hash = prior["config_hash"]
    if changes.get("config_hash") is not None:
        config_hash = changes["config_hash"]
    elif isinstance(changes.get("config"), dict):
        config_hash = sha(canonical(changes["config"]))
    return {"creator_ref": changes.get("creator_ref",
                                       prior["creator_ref"]),
            "model_ref": changes.get("model_ref",
                                     prior["model_ref"]),
            "config_hash": config_hash,
            "purpose_scope": changes.get("purpose_scope",
                                         prior["purpose_scope"]),
            "sponsor_ref": changes.get("sponsor_ref",
                                       prior["sponsor_ref"]),
            "expires_at": changes.get("expires_at",
                                      prior["expires_at"]),
            "issued_at": now}


def _amend_base(prior, changes, now):
    reg = _amend_reg(prior, changes, now)
    supersedes = {"certificate_id": prior["certificate_id"],
                  "record_hash": prior["record_hash"]}
    return _cert_base(reg, prior["agent_ref"], supersedes,
                      prior["record_hash"])


def fixture_sign_amendment(prior, changes, now):
    base = _amend_base(prior, changes, now)
    probe = dict(base)
    probe["certificate_id"] = _certificate_id(base)
    return sign(_record_hash(probe), CREATOR_KEY_REF)


def _rev_base(cert, signer_ref, ts, prev_hash):
    return {"record_type": "genesis_revocation",
            "certificate_id": cert["certificate_id"],
            "agent_ref": cert["agent_ref"],
            "signer_ref": signer_ref, "ts": ts,
            "prev_hash": prev_hash, "value_class": VALUE_CLASS}


def fixture_sign_revocation(cert, signer_ref, ts, prev_hash):
    base = _rev_base(cert, signer_ref, ts, prev_hash)
    key = CREATOR_KEY_REF if signer_ref == cert["creator_ref"] \
        else SPONSOR_KEY_REF
    return sign(_record_hash(base), key)


# ---------- scope validation (spec 4.3 / 5.4) ----------

def _scope_error(scope):
    """Return (code, detail) or None. An absent/empty member is
    SCOPE_INCOMPLETE; an out-of-vocabulary value is
    SCOPE_VOCABULARY_UNKNOWN."""
    if not isinstance(scope, dict):
        return ("SCOPE_INCOMPLETE", "purpose_scope_missing")
    if set(scope) - SCOPE_FIELDS:
        return ("SCOPE_INCOMPLETE",
                "unknown scope member: %s"
                % ",".join(sorted(set(scope) - SCOPE_FIELDS)))
    for member, vocab in (("action_types", ACTION_TYPES),
                          ("counterparty_classes",
                           COUNTERPARTY_CLASSES),
                          ("resource_classes", RESOURCE_CLASSES)):
        v = scope.get(member)
        if not isinstance(v, list) or not v:
            return ("SCOPE_INCOMPLETE", member)
        for item in v:
            if not isinstance(item, str) or item not in vocab:
                return ("SCOPE_VOCABULARY_UNKNOWN",
                        "%s:%s" % (member, item))
    if scope.get("max_value_class") is None:
        return ("SCOPE_INCOMPLETE", "max_value_class")
    if scope.get("max_value_class") != VALUE_CLASS:
        return ("SCOPE_VOCABULARY_UNKNOWN", "max_value_class")
    return None


# ---------- stream validation (spec 6.2 steps 1-2) ----------

def _validate_stream(records):
    """Recompute the whole presented stream. Returns
    (ok, step, code). Step 1 = hashes / linkage / fields / anchors /
    temporal monotonicity; step 2 = every signature (creator Herald
    + witness counter-signature on certificates, revoker signature
    on revocations) against the PINNED keys. Record-supplied key
    material is never read: an unexpected field fails step 1."""
    if not isinstance(records, list) or not records:
        return (False, "step1_chain_recompute", "EMPTY_STREAM")
    seen_ids = set()
    last_cert = None
    prev_rec = None
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            return (False, "step1_chain_recompute", "RECORD_NOT_OBJECT")
        rtype = rec.get("record_type")
        if rtype == "genesis_certificate":
            if set(rec) != CERT_FIELDS:
                extra = sorted(set(rec) - CERT_FIELDS)
                missing = sorted(CERT_FIELDS - set(rec))
                code = ("UNKNOWN_FIELD:%s" % extra[0]) if extra else \
                    ("MISSING_FIELD:%s" % missing[0])
                return (False, "step1_chain_recompute", code)
            if rec["value_class"] != VALUE_CLASS:
                return (False, "step1_chain_recompute", "VALUE_CLASS")
            if not _valid_ts(rec["issued_at"]) or \
                    not _valid_ts(rec["expires_at"]):
                return (False, "step1_chain_recompute", "TIMESTAMP")
            if _scope_error(rec["purpose_scope"]) is not None:
                return (False, "step1_chain_recompute", "SCOPE_SHAPE")
            if rec["certificate_id"] in seen_ids:
                return (False, "step1_chain_recompute",
                        "DUPLICATE_CERTIFICATE_ID")
            seen_ids.add(rec["certificate_id"])
            base = _strip(rec, ("certificate_id", "record_hash",
                                "signatures"))
            if _certificate_id(base) != rec["certificate_id"]:
                return (False, "step1_chain_recompute",
                        "CERTIFICATE_ID_MISMATCH")
            if _record_hash(rec) != rec["record_hash"]:
                return (False, "step1_chain_recompute",
                        "RECORD_HASH_MISMATCH")
            if i == 0:
                # Anchor presence is required: a first certificate
                # either cites the genesis seed, or (an amendment
                # presented standalone) its supersedes record.
                if rec["supersedes"] is None:
                    if rec["prev_hash"] != _seed_hash(rec["agent_ref"]):
                        return (False, "step1_chain_recompute",
                                "ANCHOR_MISSING")
                elif rec["prev_hash"] != \
                        rec["supersedes"].get("record_hash"):
                    return (False, "step1_chain_recompute",
                            "SUPERSEDES_LINKAGE")
            else:
                if rec["prev_hash"] != prev_rec["record_hash"]:
                    return (False, "step1_chain_recompute",
                            "CHAIN_LINKAGE")
                if rec["supersedes"] is None or last_cert is None or \
                        rec["supersedes"].get("certificate_id") != \
                        last_cert["certificate_id"] or \
                        rec["supersedes"].get("record_hash") != \
                        last_cert["record_hash"]:
                    return (False, "step1_chain_recompute",
                            "SUPERSEDES_LINKAGE")
                if rec["agent_ref"] != last_cert["agent_ref"]:
                    return (False, "step1_chain_recompute",
                            "AGENT_REF_CHANGE")
                if rec["issued_at"] <= prev_rec_ts(records, i):
                    return (False, "step1_chain_recompute",
                            "TEMPORAL_NON_MONOTONIC")
            last_cert = rec
        elif rtype == "genesis_revocation":
            if set(rec) != REV_FIELDS:
                return (False, "step1_chain_recompute",
                        "REVOCATION_FIELDS")
            if rec["value_class"] != VALUE_CLASS or \
                    not _valid_ts(rec["ts"]):
                return (False, "step1_chain_recompute",
                        "REVOCATION_SHAPE")
            if _record_hash(rec) != rec["record_hash"]:
                return (False, "step1_chain_recompute",
                        "RECORD_HASH_MISMATCH")
            if i == 0 or rec["prev_hash"] != \
                    prev_rec["record_hash"]:
                return (False, "step1_chain_recompute",
                        "CHAIN_LINKAGE")
            if rec["certificate_id"] not in seen_ids:
                return (False, "step1_chain_recompute",
                        "REVOCATION_TARGET_UNKNOWN")
            if rec["ts"] < prev_rec_ts(records, i):
                return (False, "step1_chain_recompute",
                        "TEMPORAL_NON_MONOTONIC")
        else:
            return (False, "step1_chain_recompute",
                    "RECORD_TYPE_UNKNOWN")
        prev_rec = rec
    # Step 2: every signature, cryptographically, pinned keys only.
    certs_by_id = {r["certificate_id"]: r for r in records
                   if r.get("record_type") == "genesis_certificate"}
    for rec in records:
        sigs = rec.get("signatures")
        if not isinstance(sigs, dict):
            return (False, "step2_signatures", "SIGNATURES_MISSING")
        if rec["record_type"] == "genesis_certificate":
            if set(sigs) != {"creator", "witness"}:
                return (False, "step2_signatures",
                        "COUNTER_SIGNATURE_MISSING")
            if not _verify_sig(rec["record_hash"], sigs["creator"],
                               CREATOR_KEY_REF):
                return (False, "step2_signatures",
                        "CREATOR_SIGNATURE_INVALID")
            if not _verify_sig(rec["record_hash"], sigs["witness"],
                               WITNESS_KEY_REF):
                return (False, "step2_signatures",
                        "WITNESS_SIGNATURE_INVALID")
        else:
            if set(sigs) != {"revoker"}:
                return (False, "step2_signatures",
                        "REVOKER_SIGNATURE_MISSING")
            cert = certs_by_id[rec["certificate_id"]]
            if rec["signer_ref"] == cert["creator_ref"]:
                key = CREATOR_KEY_REF
            elif cert["sponsor_ref"] != "absent" and \
                    rec["signer_ref"] == cert["sponsor_ref"]:
                key = SPONSOR_KEY_REF
            else:
                return (False, "step2_signatures",
                        "REVOKER_NOT_AUTHORIZED")
            if not _verify_sig(rec["record_hash"], sigs["revoker"],
                               key):
                return (False, "step2_signatures",
                        "REVOKER_SIGNATURE_INVALID")
    return (True, None, None)


def prev_rec_ts(records, i):
    prev = records[i - 1]
    return prev["issued_at"] if prev.get("record_type") == \
        "genesis_certificate" else prev["ts"]


def _cert_state(cert, records, now):
    """Derived from the signed stream only (never stored)."""
    for rec in records:
        if rec.get("record_type") == "genesis_certificate" and \
                isinstance(rec.get("supersedes"), dict) and \
                rec["supersedes"].get("certificate_id") == \
                cert["certificate_id"]:
            return "SUPERSEDED"
    for rec in records:
        if rec.get("record_type") == "genesis_revocation" and \
                rec.get("certificate_id") == cert["certificate_id"]:
            return "REVOKED"
    if now >= cert["expires_at"]:
        return "EXPIRED"
    return "ACTIVE"


def _family_state(fam, now):
    certs = [r for r in fam["records"]
             if r["record_type"] == "genesis_certificate"]
    if not certs:
        return "NONE"
    return _cert_state(certs[-1], fam["records"], now)


# ---------- store ----------

def data_dir():
    return os.environ.get(
        "GENESIS_DATA_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "data"))


def _store_path():
    return os.path.join(data_dir(), "store.json")


def load_store():
    p = _store_path()
    if not os.path.exists(p):
        return {"families": {}, "metering": []}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _validate_store(store):
    """Whole-store validation pre-write: every family's stream must
    recompute, every anchor (head_hash + record_count) must match
    its derived value, every metering record must be test-class."""
    for agent, fam in store["families"].items():
        ok, step, code = _validate_stream(fam["records"])
        if not ok:
            raise ToolError("STORE_VALIDATION_FAILED:%s:%s"
                            % (step, code))
        if fam["head_hash"] != fam["records"][-1]["record_hash"]:
            raise ToolError("STORE_VALIDATION_FAILED:head_anchor")
        if fam["record_count"] != len(fam["records"]):
            raise ToolError("STORE_VALIDATION_FAILED:record_count")
        if fam["agent_ref"] != agent:
            raise ToolError("STORE_VALIDATION_FAILED:agent_ref")
    for m in store["metering"]:
        if m.get("value_class") != VALUE_CLASS:
            raise ToolError("STORE_VALIDATION_FAILED:metering")


def save_store(store):
    _validate_store(store)
    os.makedirs(data_dir(), exist_ok=True)
    with open(_store_path(), "w", encoding="utf-8") as f:
        f.write(json.dumps(store, sort_keys=True))


def _find_cert(store, certificate_id):
    for agent, fam in store["families"].items():
        for rec in fam["records"]:
            if rec.get("certificate_id") == certificate_id and \
                    rec["record_type"] == "genesis_certificate":
                return fam, rec
    return None, None


def _meter_registration(store, cert):
    # Spec 9.1: registration is FREE - a zero-value Meter record is
    # still emitted, so the funnel is counted, not invisible.
    store["metering"].append({
        "record_type": "meter_record", "product": PRODUCT,
        "event": "genesis_registration",
        "certificate_id": cert["certificate_id"], "units": 1,
        "amount_minor": 0, "price_shape": PRICE_SHAPE_REGISTER,
        "value_class": VALUE_CLASS})


def _meter_verification(cert_id):
    return {"record_type": "meter_record", "product": PRODUCT,
            "event": "genesis_verification",
            "certificate_id": cert_id, "units": 1,
            "price_shape": PRICE_SHAPE_VERIFY,
            "value_class": VALUE_CLASS}


# ---------- party surface: register / amend / revoke ----------

def certificate_register(args):
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("creator_ref", "model_ref", "config",
                           "config_hash", "purpose_scope",
                           "sponsor_ref", "expires_at",
                           "creator_signature", "purpose_text", "now"))
    creator = _req_str(args, "creator_ref")
    model = _req_str(args, "model_ref")
    config = _req_obj(args, "config")
    config_hash = _req_str(args, "config_hash")
    creator_sig = _req_str(args, "creator_signature")
    sponsor = args.get("sponsor_ref")
    if sponsor is not None:
        sponsor = _req_str(args, "sponsor_ref")
    expires = args.get("expires_at")
    if expires is not None and not _valid_ts(expires):
        raise ToolError("expires_at must be an ISO timestamp")
    purpose_text = args.get("purpose_text")
    if purpose_text is not None and \
            (not isinstance(purpose_text, str) or
             len(purpose_text) > MAX_STR):
        raise ToolError("purpose_text must be a string (<= %d chars)"
                        % MAX_STR)
    if not isinstance(args.get("purpose_scope"), dict):
        raise ToolError("argument must be an object: purpose_scope")
    now = _now_arg(args)
    if expires is not None and expires <= now:
        raise ToolError("expires_at must be after issued_at")
    reg = _reg_fields({**args, "now": now})
    agent = _mint_agent_ref(creator, model, config_hash)
    store = load_store()
    fam = store["families"].get(agent)
    # Named refusals in spec 5.4 table order.
    if fam is not None and _family_state(fam, now) == "ACTIVE":
        return _refusal("DUPLICATE_ACTIVE_CERTIFICATE", agent)
    scope_err = _scope_error(args.get("purpose_scope"))
    if scope_err is not None:
        return _refusal(scope_err[0], scope_err[1])
    if sha(canonical(config)) != config_hash:
        return _refusal("CONFIG_HASH_MISMATCH",
                        "recomputed config hash differs")
    base = _cert_base(reg, agent, None, _seed_hash(agent))
    probe = dict(base)
    probe["certificate_id"] = _certificate_id(base)
    prospective_hash = _record_hash(probe)
    if not _verify_sig(prospective_hash, creator_sig, CREATOR_KEY_REF):
        return _refusal("HERALD_SIGNATURE_INVALID",
                        "creator signature does not verify against "
                        "the pinned fixture key")
    cert = _finalize_cert(base, creator_sig)
    if fam is None:
        fam = {"agent_ref": agent, "records": [],
               "head_hash": None, "record_count": 0, "unsealed": {}}
        store["families"][agent] = fam
    else:
        # Family exists in a terminal state (REVOKED / EXPIRED /
        # SUPERSEDED head): spec 3.3 governs the ACTIVE case only.
        # Build pin: a fresh birth for the same minted agent_ref is
        # refused rather than forking the signed stream; a new
        # identity (creator/model/config change) mints a new ref.
        return _refusal("AGENT_FAMILY_TERMINAL",
                        "agent family exists and is not ACTIVE")
    fam["records"].append(cert)
    fam["head_hash"] = cert["record_hash"]
    fam["record_count"] = len(fam["records"])
    if purpose_text is not None:
        fam["unsealed"][cert["certificate_id"]] = purpose_text
    _meter_registration(store, cert)
    save_store(store)
    return {**cert, "state": "ACTIVE", "idempotent": False}


def certificate_amend(args):
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("certificate_id", "changes",
                           "creator_signature", "purpose_text", "now"))
    cid = _req_str(args, "certificate_id")
    changes = _req_obj(args, "changes")
    _check_no_extra(changes, ("creator_ref", "model_ref", "config",
                              "config_hash", "purpose_scope",
                              "sponsor_ref", "expires_at"))
    creator_sig = _req_str(args, "creator_signature")
    now = _now_arg(args)
    store = load_store()
    fam, prior = _find_cert(store, cid)
    if prior is None:
        return _refusal("CERTIFICATE_NOT_FOUND", cid)
    certs = [r for r in fam["records"]
             if r["record_type"] == "genesis_certificate"]
    if certs[-1]["certificate_id"] != cid or \
            _cert_state(prior, fam["records"], now) != "ACTIVE":
        return _refusal("AMENDMENT_TARGET_INVALID",
                        "target is not the current ACTIVE head")
    if now <= prior["issued_at"]:
        return _refusal("TEMPORAL_NON_MONOTONIC",
                        "amendment must be after the prior "
                        "certificate")
    if "purpose_scope" in changes:
        scope_err = _scope_error(changes["purpose_scope"])
        if scope_err is not None:
            return _refusal(scope_err[0], scope_err[1])
    if isinstance(changes.get("config"), dict) and \
            changes.get("config_hash") is not None and \
            sha(canonical(changes["config"])) != \
            changes["config_hash"]:
        return _refusal("CONFIG_HASH_MISMATCH",
                        "recomputed config hash differs")
    base = _amend_base(prior, changes, now)
    probe = dict(base)
    probe["certificate_id"] = _certificate_id(base)
    if not _verify_sig(_record_hash(probe), creator_sig,
                       CREATOR_KEY_REF):
        return _refusal("HERALD_SIGNATURE_INVALID",
                        "creator signature does not verify against "
                        "the pinned fixture key")
    cert = _finalize_cert(base, creator_sig)
    fam["records"].append(cert)
    fam["head_hash"] = cert["record_hash"]
    fam["record_count"] = len(fam["records"])
    purpose_text = args.get("purpose_text")
    if purpose_text is not None:
        if not isinstance(purpose_text, str) or \
                len(purpose_text) > MAX_STR:
            raise ToolError("purpose_text must be a string")
        fam["unsealed"][cert["certificate_id"]] = purpose_text
    save_store(store)
    return {**cert, "state": "ACTIVE", "idempotent": False,
            "supersedes_certificate_id": cid}


def certificate_revoke(args):
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("certificate_id", "signer_ref",
                           "signature", "now"))
    cid = _req_str(args, "certificate_id")
    signer_ref = _req_str(args, "signer_ref")
    signature = _req_str(args, "signature")
    now = _now_arg(args)
    store = load_store()
    fam, cert = _find_cert(store, cid)
    if cert is None:
        return _refusal("CERTIFICATE_NOT_FOUND", cid)
    certs = [r for r in fam["records"]
             if r["record_type"] == "genesis_certificate"]
    if certs[-1]["certificate_id"] != cid or \
            _cert_state(cert, fam["records"], now) != "ACTIVE":
        return _refusal("REVOCATION_TARGET_INVALID",
                        "target is not the current ACTIVE head")
    if signer_ref != cert["creator_ref"] and \
            not (cert["sponsor_ref"] != "absent" and
                 signer_ref == cert["sponsor_ref"]):
        return _refusal("HERALD_SIGNATURE_INVALID",
                        "signer is neither creator nor sponsor of "
                        "record")
    head = fam["records"][-1]
    head_ts = head["issued_at"] if head["record_type"] == \
        "genesis_certificate" else head["ts"]
    if now < head_ts:
        return _refusal("TEMPORAL_NON_MONOTONIC",
                        "revocation precedes the stream head")
    base = _rev_base(cert, signer_ref, now, fam["head_hash"])
    key = CREATOR_KEY_REF if signer_ref == cert["creator_ref"] \
        else SPONSOR_KEY_REF
    if not _verify_sig(_record_hash(base), signature, key):
        return _refusal("HERALD_SIGNATURE_INVALID",
                        "revoker signature does not verify against "
                        "the pinned fixture key")
    rec = dict(base)
    rec["record_hash"] = _record_hash(base)
    rec["signatures"] = {"revoker": signature}
    fam["records"].append(rec)
    fam["head_hash"] = rec["record_hash"]
    fam["record_count"] = len(fam["records"])
    save_store(store)
    return {**rec, "state": "REVOKED"}


# ---------- party surface: get / export (constructed serves) ----------

def _downgraded_export(certificate_id, step, code, agent_ref=None):
    out = {"export_label": "DOWNGRADED_CERTIFICATE_EXPORT",
           "verified": False, "verdict": "BROKEN:%s" % step,
           "first_failure": {"step": step, "code": code},
           "certificate_id": certificate_id, "signed": False,
           "value_class": VALUE_CLASS}
    if agent_ref is not None:
        out["agent_ref"] = agent_ref
    return out


def certificate_get(args):
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("certificate_id", "now"))
    cid = _req_str(args, "certificate_id")
    now = _now_arg(args)
    store = load_store()
    fam, cert = _find_cert(store, cid)
    if cert is None:
        raise ToolError("CERTIFICATE_NOT_FOUND")
    # Constructed serve: the stored stream is re-validated from its
    # verified components before anything is served from it.
    ok, step, code = _validate_stream(fam["records"])
    if not ok:
        return _downgraded_export(cid, step, code, fam["agent_ref"])
    out = {"product": PRODUCT, "tool_version": TOOL_VERSION,
           "scope": SCOPE, "certificate": cert,
           "state": _cert_state(cert, fam["records"], now),
           "stream_head": fam["records"][-1]["record_hash"],
           "record_count": len(fam["records"]),
           "value_class": VALUE_CLASS}
    text = fam.get("unsealed", {}).get(cid)
    if text is not None:
        out["unsealed_summary"] = {"label": "unsealed_summary",
                                   "purpose_text": text}
    return out


def certificate_export(args):
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("certificate_id", "certificate"))
    presented = args.get("certificate")
    if presented is not None:
        # Imported artifact path (spec 6.4): a presented certificate
        # that fails recompute - including an unwitnessed one -
        # exports downgraded only. There is no upgrade path.
        if not isinstance(presented, dict):
            raise ToolError("certificate must be an object")
        ok, step, code = _validate_stream([presented])
        cid = presented.get("certificate_id")
        if not ok:
            return _downgraded_export(cid, step, code,
                                      presented.get("agent_ref"))
        anchor = sha(presented["record_hash"] + "|1")
        return {"export_label": "GENESIS_CERTIFICATE_EXPORT",
                "verified": True, "agent_ref": presented["agent_ref"],
                "certificate_id": cid, "records": [presented],
                "head_hash": presented["record_hash"],
                "record_count": 1,
                "anchor_signature": sign(anchor, WITNESS_KEY_REF),
                "value_class": VALUE_CLASS}
    cid = _req_str(args, "certificate_id")
    store = load_store()
    fam, cert = _find_cert(store, cid)
    if cert is None:
        raise ToolError("CERTIFICATE_NOT_FOUND")
    ok, step, code = _validate_stream(fam["records"])
    if not ok:
        return _downgraded_export(cid, step, code, fam["agent_ref"])
    head = fam["records"][-1]["record_hash"]
    count = len(fam["records"])
    anchor = sha(head + "|" + str(count))
    out = {"export_label": "GENESIS_CERTIFICATE_EXPORT",
           "verified": True, "agent_ref": fam["agent_ref"],
           "certificate_id": cid,
           "records": [dict(r) for r in fam["records"]],
           "head_hash": head, "record_count": count,
           "anchor_signature": sign(anchor, WITNESS_KEY_REF),
           "value_class": VALUE_CLASS}
    if fam.get("unsealed"):
        out["unsealed_summaries"] = {
            k: {"label": "unsealed_summary", "purpose_text": v}
            for k, v in fam["unsealed"].items()}
    return out


# ---------- offline verification (spec 6.2, pure) ----------

def certificate_verify(args):
    """Artifact + pinned keys only; no Genesis state is read.
    Any failing step names itself in first_failure."""
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("certificate", "family_records", "config",
                           "now"))
    cert = args.get("certificate")
    now = _now_arg(args)
    base = {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "value_class": VALUE_CLASS}
    if not isinstance(cert, dict):
        return {**base, "receipt_id": None, "certificate_id": None,
                "issued_at": now, "seal_valid": False,
                "verdict": "BROKEN",
                "first_failure": {"step": "step1_chain_recompute",
                                  "code": "CERTIFICATE_NOT_OBJECT"},
                "config_body": "not-presented",
                "value_class": VALUE_CLASS}
    family = args.get("family_records") or []
    if not isinstance(family, list):
        raise ToolError("family_records must be an array")
    stream = [cert] + list(family)
    ok, step, code = _validate_stream(stream)
    failure = None
    if not ok:
        fail_step = "step1_chain_recompute" if step.startswith(
            "step1") else "step2_signatures"
        failure = {"step": fail_step, "code": code}
    config_body = "not-presented"
    if failure is None and args.get("config") is not None:
        config_body = "presented"
        if not isinstance(args["config"], dict) or \
                sha(canonical(args["config"])) != cert["config_hash"]:
            failure = {"step": "step3_config_binding",
                       "code": "CONFIG_HASH_MISMATCH"}
    if failure is not None:
        verdict = "BROKEN"
        seal_valid = False
    else:
        seal_valid = True
        verdict = _cert_state(cert, stream, now)
        if verdict == "ACTIVE":
            verdict = "SEAL_VALID"
    summary = {"creator_hash": sha(cert.get("creator_ref", "")),
               "model_hash": sha(cert.get("model_ref", "")),
               "config_hash": cert.get("config_hash"),
               "scope_hash": sha(canonical(
                   cert.get("purpose_scope")))}
    receipt = {**base, "receipt_type": "genesis_verify_receipt",
               "certificate_id": cert.get("certificate_id"),
               "issued_at": now, "seal_valid": seal_valid,
               "verdict": verdict, "sealed_summary": summary,
               "config_body": config_body,
               "meter_record": _meter_verification(
                   cert.get("certificate_id")),
               "signer": SIGNER_LABEL}
    if failure is not None:
        receipt["first_failure"] = failure
    receipt["receipt_id"] = "rcpt_" + sha(canonical(
        _strip(receipt, ("meter_record",))))[:16]
    receipt["signature"] = sign(
        sha(canonical(_strip(receipt, ("signature",)))),
        WITNESS_KEY_REF)
    if receipt["signature"] is None:
        raise ToolError("witness fixture key unavailable")
    return receipt


# ---------- out-of-purpose detection (spec 3.5 / 6.3, pure) ----------

def _action_malformed(action):
    if not isinstance(action, dict):
        return "not_an_object"
    for f in ACTION_FIELDS:
        if f not in action:
            return "missing_field:%s" % f
    for f in ("record_id", "agent_ref", "action_type",
              "counterparty_class", "resource_class"):
        if not isinstance(action[f], str) or not action[f] or \
                len(action[f]) > MAX_STR:
            return "field_not_string:%s" % f
    if not _valid_ts(action["ts"]):
        return "ts_invalid"
    if action["value_class"] != VALUE_CLASS:
        return "value_class_not_test"
    return None


def _classify(cert, action):
    scope = cert["purpose_scope"]
    if action["action_type"] not in ACTION_TYPES or \
            action["counterparty_class"] not in \
            COUNTERPARTY_CLASSES or \
            action["resource_class"] not in RESOURCE_CLASSES:
        return ("INDETERMINATE", None, "unmapped")
    if action["action_type"] not in scope["action_types"]:
        return ("OUT_OF_PURPOSE", "action_types", None)
    if action["counterparty_class"] not in \
            scope["counterparty_classes"]:
        return ("OUT_OF_PURPOSE", "counterparty_classes", None)
    if action["resource_class"] not in scope["resource_classes"]:
        return ("OUT_OF_PURPOSE", "resource_classes", None)
    return ("IN_PURPOSE", None, None)


def purpose_detect(args):
    """Pure over presented artifacts: certificate chain + action
    records + pinned keys. Emits records; blocks nothing, mutates
    nothing presented, changes no certificate state (L3)."""
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("certificates", "action_records", "now"))
    certs_in = _req_list(args, "certificates")
    actions = _req_list(args, "action_records")
    if len(actions) > MAX_ACTIONS:
        raise ToolError("too many action records (max %d)"
                        % MAX_ACTIONS)
    now = _now_arg(args)
    if certs_in:
        ok, step, code = _validate_stream(certs_in)
        if not ok:
            # Detection over a broken seal would launder it (5.4).
            return _refusal("DETECTION_CERTIFICATE_BROKEN",
                            "%s:%s" % (step, code))
    certs = [r for r in certs_in
             if r.get("record_type") == "genesis_certificate"]
    # Windows: [issued_at, successor issued_at) per certificate.
    windows = []
    for i, c in enumerate(certs):
        end = certs[i + 1]["issued_at"] if i + 1 < len(certs) \
            else None
        windows.append((c, end))
    run_id = "run_" + sha(canonical(
        {"certificates": certs_in, "action_records": actions}))[:16]
    prev_hash = sha("eclipse-genesis/detect" + run_id)
    records = []
    refused = []
    counts = {"IN_PURPOSE": 0, "OUT_OF_PURPOSE": 0,
              "INDETERMINATE": 0}
    judged = []
    for action in actions:
        bad = _action_malformed(action)
        if bad is not None:
            ref = action.get("record_id") if isinstance(
                action, dict) else None
            refused.append({"action_record_ref": ref,
                            "refusal": "ACTION_RECORD_MALFORMED",
                            "detail": bad,
                            "value_class": VALUE_CLASS})
            continue
        chosen = None
        for c, end in windows:
            if c["agent_ref"] == action["agent_ref"] and \
                    c["issued_at"] <= action["ts"] and \
                    (end is None or action["ts"] < end):
                chosen = c
                break
        rec = {"record_type": "genesis_detection", "run_id": run_id,
               "action_record_ref": action["record_id"],
               "action_record_hash": sha(canonical(action)),
               "action_ts": action["ts"],
               "detector_methodology_version":
               DETECTOR_METHODOLOGY_VERSION, "ts": now,
               "prev_hash": prev_hash, "value_class": VALUE_CLASS}
        if chosen is None:
            rec.update({"certificate_id": None,
                        "record_hash": None,
                        "classification": "INDETERMINATE",
                        "reason": "no-certificate-at-time",
                        "certificate_status": "none"})
        else:
            cls, clause, reason = _classify(chosen, action)
            # Spec 4.5: certificate_id + record_hash OF THE
            # CERTIFICATE judged against.
            rec.update({"certificate_id": chosen["certificate_id"],
                        "record_hash": chosen["record_hash"],
                        "classification": cls,
                        "certificate_status": _cert_state(
                            chosen, certs_in, now).lower()})
            if clause is not None:
                rec["clause"] = clause
            if reason is not None:
                rec["reason"] = reason
            if chosen["record_hash"] not in judged:
                judged.append(chosen["record_hash"])
        counts[rec["classification"]] += 1
        # The detection record's own chain hash (its record_hash
        # field above is the certificate's, per spec 4.5).
        rec["detection_hash"] = sha(canonical(_strip(
            rec, ("detection_hash", "witness_signature"))) +
            "|" + rec["prev_hash"])
        rec["witness_signature"] = sign(rec["detection_hash"],
                                         WITNESS_KEY_REF)
        if rec["witness_signature"] is None:
            raise ToolError("witness fixture key unavailable")
        prev_hash = rec["detection_hash"]
        records.append(rec)
    receipt = {"record_type": "genesis_detection_run",
               "run_id": run_id, "issued_at": now,
               "records": records, "refused_records": refused,
               "counts": counts,
               "certificate_hashes_judged": judged,
               "detector_methodology_version":
               DETECTOR_METHODOLOGY_VERSION,
               "meter_record": _meter_verification(
                   certs[0]["certificate_id"] if certs else None),
               "signer": SIGNER_LABEL, "value_class": VALUE_CLASS}
    receipt["signature"] = sign(
        sha(canonical(_strip(receipt, ("signature",)))),
        WITNESS_KEY_REF)
    if receipt["signature"] is None:
        raise ToolError("witness fixture key unavailable")
    return receipt


def downgraded_export_for(cert):
    """Spec 6.4 helper used by certificate_export's presented path
    and exposed for the bench: broken/unwitnessed artifacts export
    downgraded only."""
    return certificate_export({"certificate": cert})


# ---------- operator surface (read-only, derived) ----------

def family_list(args):
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ("now",))
    now = _now_arg(args)
    store = load_store()
    out = []
    for agent, fam in sorted(store["families"].items()):
        ok, step, code = _validate_stream(fam["records"])
        out.append({
            "agent_ref": agent,
            "certificate_ids": [r["certificate_id"] for r in
                                fam["records"] if r["record_type"] ==
                                "genesis_certificate"],
            "head_hash": fam["records"][-1]["record_hash"]
            if fam["records"] else None,
            "record_count": len(fam["records"]),
            "state": _family_state(fam, now) if ok else "BROKEN",
            "seal_ok": ok, "value_class": VALUE_CLASS})
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "families": out, "count": len(out),
            "value_class": VALUE_CLASS}


def metering_read(args):
    fenced = _fence_result()
    if fenced:
        return fenced
    _check_no_extra(args, ())
    store = load_store()
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "metering": store["metering"],
            "count": len(store["metering"]),
            "value_class": VALUE_CLASS}


PARTY_TOOLS = {"genesis_certificate_register": certificate_register,
               "genesis_certificate_amend": certificate_amend,
               "genesis_certificate_revoke": certificate_revoke,
               "genesis_certificate_get": certificate_get,
               "genesis_certificate_verify": certificate_verify,
               "genesis_purpose_detect": purpose_detect,
               "genesis_certificate_export": certificate_export}
OPERATOR_TOOLS = {"genesis_family_list": family_list,
                  "genesis_metering_read": metering_read}
