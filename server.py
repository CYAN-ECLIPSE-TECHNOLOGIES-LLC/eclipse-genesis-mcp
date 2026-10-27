#!/usr/bin/env python3
# Eclipse Genesis MCP server (spec: SPEC.md).
# Copyright 2026 Cyan Eclipse Technologies LLC - cetech.ai
"""Surfaces are disjoint, selected by GENESIS_SURFACE (party
default, operator). A verb from the other surface returns the
identical unknown-tool refusal as a nonsense name. Genesis detects,
never blocks: no verb exists that intercepts, prevents, suspends,
penalises, edits, un-seals, or deletes anything. Signing is an HMAC
fixture stand-in for Herald RS256, disclosed here as on every face.
Crash-proof envelope: malformed lines and failing calls produce
structured errors; the stdio loop survives every one."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import genesis  # noqa: E402

SERVER_NAME = "io.github.CYAN-ECLIPSE-TECHNOLOGIES-LLC/eclipse-genesis-mcp"
SERVER_VERSION = genesis.TOOL_VERSION
_STR = {"type": "string"}
_OBJ = {"type": "object"}


def _obj(props, required):
    return {"type": "object", "properties": props,
            "required": required, "additionalProperties": False}


DESCRIPTIONS = {
    "genesis_certificate_register": "Register a fixture agent: "
        "creator, model, config hash, and declared purpose scope "
        "are sealed into a Herald-signed (fixture HMAC stand-in), "
        "witness counter-signed birth certificate. Sealing only - "
        "no declaration is truth-checked or endorsed.",
    "genesis_certificate_amend": "Amend by issuing a NEW "
        "certificate citing supersedes; the prior certificate "
        "becomes SUPERSEDED and stays verifiable as history. "
        "Sealed fields are never edited.",
    "genesis_certificate_revoke": "Append a Herald-signed "
        "revocation record (creator or sponsor of record); the "
        "certificate becomes REVOKED for current standing and "
        "still verifies historically.",
    "genesis_certificate_get": "Fetch a certificate plus its "
        "derived state and stream head (head hash + record count).",
    "genesis_certificate_verify": "Offline recompute over a "
        "presented certificate (+ family records): seal, both "
        "signatures, config binding, status. Pure function; keys "
        "are pinned out-of-band. Metering point.",
    "genesis_purpose_detect": "Classify presented witnessed action "
        "records (Docket/Meter grammar) against the sealed purpose "
        "scope of the certificate in force at each action's time. "
        "Detection only - blocks nothing, mutates nothing. "
        "Metering point.",
    "genesis_certificate_export": "Export the full ordered record "
        "stream for a certificate family, or a presented "
        "certificate; broken/unwitnessed artifacts export as "
        "DOWNGRADED_CERTIFICATE_EXPORT only.",
    "genesis_family_list": "Operator: certificate families, "
                           "derived states, seal status (read-only).",
    "genesis_metering_read": "Operator: Meter-grammar metering "
                             "records emitted so far (read-only).",
}
SCHEMAS = {
    "genesis_certificate_register": _obj(
        {"creator_ref": _STR, "model_ref": _STR, "config": _OBJ,
         "config_hash": _STR, "purpose_scope": _OBJ,
         "sponsor_ref": _STR, "expires_at": _STR,
         "creator_signature": _STR, "purpose_text": _STR,
         "now": _STR},
        ["creator_ref", "model_ref", "config", "config_hash",
         "purpose_scope", "creator_signature"]),
    "genesis_certificate_amend": _obj(
        {"certificate_id": _STR, "changes": _OBJ,
         "creator_signature": _STR, "purpose_text": _STR,
         "now": _STR},
        ["certificate_id", "changes", "creator_signature"]),
    "genesis_certificate_revoke": _obj(
        {"certificate_id": _STR, "signer_ref": _STR,
         "signature": _STR, "now": _STR},
        ["certificate_id", "signer_ref", "signature"]),
    "genesis_certificate_get": _obj(
        {"certificate_id": _STR, "now": _STR}, ["certificate_id"]),
    "genesis_certificate_verify": _obj(
        {"certificate": _OBJ, "family_records": {"type": "array"},
         "config": _OBJ, "now": _STR}, ["certificate"]),
    "genesis_purpose_detect": _obj(
        {"certificates": {"type": "array"},
         "action_records": {"type": "array"}, "now": _STR},
        ["certificates", "action_records"]),
    "genesis_certificate_export": _obj(
        {"certificate_id": _STR, "certificate": _OBJ}, []),
    "genesis_family_list": _obj({"now": _STR}, []),
    "genesis_metering_read": _obj({}, []),
}


def surface_tools():
    if os.environ.get("GENESIS_SURFACE", "party") == "operator":
        return genesis.OPERATOR_TOOLS
    return genesis.PARTY_TOOLS


def dispatch(name, args):
    tools = surface_tools()
    if name not in tools:
        return {"refusal": "NO_SUCH_TOOL",
                "detail": "%r is not a tool here." % (name,)}
    if not isinstance(args, dict):
        raise genesis.ToolError("arguments must be an object")
    return tools[name](args)


def handle(req):
    if not isinstance(req, dict):
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600,
                          "message": "request must be an object"}}
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME,
                           "version": SERVER_VERSION}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": n, "description": DESCRIPTIONS[n],
             "inputSchema": SCHEMAS[n]} for n in surface_tools()]}}
    if method == "tools/call":
        params = req.get("params", {})
        if not isinstance(params, dict):
            params = {}
        try:
            result = dispatch(params.get("name"),
                              params.get("arguments", {}))
            is_err = isinstance(result, dict) and "refusal" in result
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "isError": is_err,
                "content": [{"type": "text",
                             "text": json.dumps(result,
                                                sort_keys=True)}]}}
        except genesis.ToolError as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "isError": True,
                "content": [{"type": "text", "text": json.dumps(
                    {"error": str(e)}, sort_keys=True)}]}}
        except Exception as e:  # crash-proof envelope: never raise
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "isError": True,
                "content": [{"type": "text", "text": json.dumps(
                    {"error": "INTERNAL_REFUSED:%s"
                              % type(e).__name__},
                    sort_keys=True)}]}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601,
                      "message": "method not found: %s" % method}}


def main():
    # Spec 7.3 fail-closed fence: refuse startup before any input.
    refusal = genesis.config_fence_refusal()
    if refusal:
        raise SystemExit(refusal)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            resp = handle(req)
        except Exception:
            resp = {"jsonrpc": "2.0", "id": None, "result": {
                "isError": True,
                "content": [{"type": "text", "text": json.dumps(
                    {"error": "INTERNAL_REFUSED:handler"},
                    sort_keys=True)}]}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
