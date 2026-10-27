# Eclipse Genesis

An agent birth-certificate issuer: at registration, the agent's
creator, model, config hash, and declared purpose scope are sealed
into a Herald-signed, hash-chained certificate. Any counterparty
can later verify the certificate offline — and, by comparing
witnessed action records against the sealed purpose scope, *detect*
action outside the declared purpose.

**Scope label: LOCAL, fixture agents/creators/keys only.** Local
stdio MCP server, Python standard library only. No live registry,
no live agent registration, no network fetch, no action
interception. Every artifact carries `value_class: "test"`.

**Status: v0.1.0 — PASS-CONDITIONAL(local/fixture).**
Exact verdict (Verity bench, 2026-10-27,
`argus101-program-20261027/wave3/bench-genesis.md`): `Eclipse Genesis — PASS-CONDITIONAL(local/fixture)`.
`certified: false` — PASS-CONDITIONAL is not CERTIFIED, and nothing
beyond local/fixture scope is claimed here. Sole condition:
full coordinated rollback is a fenced condition — external anchor required before live/multi-party use.

**Genesis detects, it never blocks.** Detection is a verdict over
presented records. Genesis never intercepts, prevents, suspends, or
punishes an action or an agent, and no verb exists that can: there
is no blocking, enforcement, editing, un-sealing, or deletion verb
on any surface (bench-checked by dispatch-table enumeration).

## What a certificate does and does not say

Permitted claim, exact sense only: "creator, model, config hash,
and declared purpose scope **as declared and sealed at
registration**, recomputable from the certificate." A certificate
proves what was *declared and sealed at registration*. It asserts
nothing about whether the declarations were true, and registration
is sealing, not endorsement. A detection verdict is stated as
"**detectable** against the sealed scope from the presented
records" — classification is over presented records against
declared scope, records may be incomplete, and `INDETERMINATE` is a
standing outcome that no summary silently drops. Historical
(superseded / revoked / expired-window) judgments are never
presented as current standing.

`purpose_text`, when supplied, is an unsealed human-readable
summary: it is carried outside the sealed canonical form and is
rendered only under the label `unsealed_summary`. The sealed
structured purpose scope is the only detection input and the only
scope any surface may quote as sealed.

Signing in v0.1 is an HMAC fixture stand-in for Herald RS256
(fixture keys only, in `keys/` at chmod 600, gitignored, disclosed
here and in code). Verification keys are pinned out-of-band by
fixed key ref; a key or key ref is never accepted from the record
under verification, and every verify path recomputes hashes from
source data — presented digests are claims. Both signatures
(creator + witness counter-signature) are cryptographically
verified on every path; verify is fail-closed on a missing pinned
key. A certificate that fails recompute exports only as
`DOWNGRADED_CERTIFICATE_EXPORT` — unsigned, `verified: false` — and
no artifact is ever upgraded post-hoc: a correction is a new
certificate.

Startup is fail-closed (spec §7.3): a live-key string, a live
registry URL or other non-local endpoint, a non-fixture
creator/agent source, `value_class` other than `test`, key material
outside local fixture `keys/`, or any network/payment module in the
tree refuses startup with `CONFIG_FENCE_REFUSED:<class>`.

**Cross-artifact fence (verbatim):** full coordinated rollback =
fenced condition — external anchor required before live/multi-party use.
The stream's genesis seed hash anchors a family locally, and each
export carries a witness-signed head anchor (head hash +
record_count); that is a local anchor only.

**Counsel gate (spec §10) — named, unbuilt:** any live phase — a
real registry accepting real registrations, certificates presented
to third parties for reliance, detection records used in disputes,
enforcement, or platform decisions, or any "registered agent"
claim towards regulated buyers — requires counsel review before
build. Live registry reliance is the §10 gate: named here, never
designed around; v0.1 contains no dormant live path, no dormant
enforcement/blocking verb of any kind, and no config flip that
turns this build live.

Metering (spec §9): registration is FREE — a zero-value Meter
record is still emitted, so the funnel is counted. Verification-
class issuances (`genesis_certificate_verify` receipts and
`genesis_purpose_detect` run receipts) carry one Meter-grammar
metering record at the $0.05/verification price shape. v0.1
implements no charge path, no payment call, and no entitlement
check — metering records only. Herald, Docket, Meter, and Till are
consumed by grammar/reference only; no code of theirs is modified
or redefined here.

## Tools

Party surface (default, `GENESIS_SURFACE=party`):

| Tool | What it does |
|---|---|
| `genesis_certificate_register` | Seal a fixture registration → certificate or named refusal (§5.4) |
| `genesis_certificate_amend` | New certificate citing `supersedes`; prior → SUPERSEDED |
| `genesis_certificate_revoke` | Herald-signed revocation record; certificate → REVOKED |
| `genesis_certificate_get` | Certificate + derived state + stream head + record count |
| `genesis_certificate_verify` | Offline §6.2 recompute over a presented certificate (+ family records) |
| `genesis_purpose_detect` | §4.5 detection run over presented action records (Docket/Meter grammar) |
| `genesis_certificate_export` | Full ordered record stream for a family, with signed head anchor |

Operator surface (`GENESIS_SURFACE=operator`):
`genesis_family_list`, `genesis_metering_read`. Surfaces are
disjoint; a verb from the other surface returns the same
unknown-tool refusal as a nonsense name.

## Fixtures

`fixtures/registration-v1.json` — a complete signed fixture
registration presentation (creator signature via the Herald
fixture interface); `fixtures/action-in-purpose.json` — a fixture
witnessed action record in Docket/Meter grammar that classifies
`IN_PURPOSE` against it. All fixtures are deterministic and carry
`value_class: "test"`.

## Run

```
python3 server.py            # MCP over stdio JSON-RPC
python3 -m unittest discover -s tests -v
```

State lives in `data/` or `GENESIS_DATA_DIR`. Python 3, standard
library only.

Powered by Cyan Eclipse Technologies — https://cetech.ai

MIT License · Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
