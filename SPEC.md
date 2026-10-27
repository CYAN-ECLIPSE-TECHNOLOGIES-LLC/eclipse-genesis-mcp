# Eclipse Genesis — Spec

**Product:** Eclipse Genesis · **Argus-101:** #17 · **Cluster:** 2 — Identity & Attestation · **Size:** M · **Price shape:** FREE registration + $0.05/verification (§9, metering only) · **Cert-scope target:** `Eclipse Genesis — <VERDICT>(local/fixture)` · **Primary gate:** counsel gate §10 — no live registry, no third-party reliance on certificates, no out-of-purpose enforcement use before clearance and re-bench

Name is a placeholder pending trademark screen.

**Powered by Cyan Eclipse Technologies** — https://cetech.ai
**Stage:** SPEC (Silas) · **Date:** 2026-10-27 · **Status:** buildable, bench-pending, no certification claimed
**Source:** `argus-101-20261027.md` #17

## 0. Scope + cert-scope target + laws binding

- **0.1 v0.1 scope — LOCAL only.** Certificate issue + verify, and out-of-purpose detection over presented fixture action records, on a local stdio MCP server (Python stdlib only, house pattern). No live registry, no live agent registration, no network fetch, no action interception. All artifacts `value_class: "test"`.
- **0.2 Cert-scope target.** `Eclipse Genesis — <VERDICT>(local/fixture)` once Verity benches §8. Before bench: "bench pending — no certification is claimed" (§11). Scope qualifier never detaches from the verdict or from any certificate (§4).
- **0.3 Laws binding.**
  - **L1 Legally-clear scope only.** v0.1 = fixture/local ladder only. Live phases are counsel-gated (§10), named there, never designed around; v0.1 contains no dormant live path.
  - **L2 Sealed means sealed.** A certificate's sealed fields (§4.2) are never edited. Change = a new certificate superseding the old (§3.4); the old certificate remains verifiable as history.
  - **L3 Genesis detects, it does not block.** Detection (§3.5) is a verdict over presented records. Genesis never intercepts, prevents, suspends, or punishes an action; it has no verb that can (§5).
  - **L4 Declared ≠ verified character.** A certificate proves what was *declared and sealed at registration* — creator, model, config hash, purpose scope. It asserts nothing about whether the declarations were true, the agent is safe, or later behaviour was in-purpose (§11).
  - **L5 Consume, never redefine.** Herald signs; Docket/Meter action records are consumed as presented artifacts in their own grammars; Continuity (#14) chains lineage after birth (§12). Genesis defines no signature scheme, action-record format, or lineage link of its own.
  - **L6 Downgrade law.** Any certificate/detection artifact that fails recompute exports downgraded, never upgraded post-hoc (§6).

## 1. Product definition

- **1.1 What it is.** An agent birth-certificate issuer: at registration, the agent's creator, model, config hash, and declared purpose scope are sealed into a Herald-signed, hash-chained certificate. Any counterparty can later verify the certificate offline — and, by comparing witnessed action records against the sealed purpose scope, *detect* action outside the declared purpose.
- **1.2 The hole it fills.** Agents appear with self-described identities and purposes that live in editable profile pages and README files: change the description and the past changes with it. A counterparty who was harmed by an agent acting far outside what it claimed to be for has no sealed, recomputable record of what was declared at the start. Genesis makes the declaration itself evidence — fixed at registration, verifiable by anyone holding the certificate, and checkable against witnessed action records.
- **1.3 What it is not.** Not a registry of record for live agents (v0.1 is local), not a licensing or approval body (registration is sealing, not endorsement — §11), not a lineage chain (Continuity, #14 — Genesis is the birth record Continuity's genesis link may cite), not an enforcement or blocking layer (L3), not a behaviour score (Doppel, #16).

## 2. Novel mechanism (verbatim) + N-check

- **2.1 Novel mechanism (one sentence, the bench's subject).** "at registration the agent's creator, model, config hash, and declared purpose scope are sealed; acting outside the declared purpose is detectable by any counterparty who checks the certificate."
- **2.2 The three parts (one seal).**
  1. **Sealed birth certificate** — creator ref, model ref, config hash, and a structured declared purpose scope (§4.3) sealed at registration: Herald-signed by the creator and counter-signed by the witness, hash-chained as the first record of the certificate's own stream (§4.1). Sealing is the act; Genesis performs no truth-check on the declarations beyond shape (§5.4) and says so (§11).
  2. **Offline certificate verification** — any holder recomputes the seal from the certificate + public keys alone (§6.2): the sealed fields are what they were at registration, or verification names the broken step. No registry lookup, no Genesis state.
  3. **Out-of-purpose detection** — a detector compares presented witnessed action records (Docket/Meter grammar, §12) against the sealed purpose scope, clause by clause, and emits a detection record (§4.5): each action classified `IN_PURPOSE`, `OUT_OF_PURPOSE:<clause>`, or `INDETERMINATE:<reason>` — unmapped action types are `INDETERMINATE`, never coerced to either side (§3.5). Detection is recomputable from (certificate, action records) alone (§6.3).
- **2.3 N-check — nearest incumbents and the defining test they fail.**
  - **Agent Cards / platform profiles:** self-asserted and editable in place; yesterday's declared purpose cannot be recomputed today, and no seal binds the declaration to a registration moment.
  - **Continuity (#14):** chains *changes* to an already-identified principal; it carries no purpose scope and performs no purpose comparison — a chain can be perfectly continuous while every action is out-of-purpose.
  - **API terms-of-service / acceptable-use policies:** prose contracts held by one platform; not sealed per-agent artifacts, not machine-checkable against witnessed action records by any counterparty.
  - **Registry listings (Bazaar catalog included):** discovery furniture; a listing describes, it does not seal, and a listing edit leaves no broken hash.
  - **Defining test (the bench runs it verbatim, §8 F-G13):** *given only a certificate + a presented set of witnessed action records + public keys, in a fresh process with no Genesis state, recompute the seal and classify every action against the sealed scope — flagging the out-of-purpose action by the clause it violates, while Genesis itself blocks nothing.* Each incumbent above fails it for the stated reason.

## 3. Lifecycle / state machine

```
  (no certificate) ──register──► SEALED ──► ACTIVE ──detect──► ACTIVE (detection record appended, §3.5)
                                      │ amend (§3.4) ──► SUPERSEDED (terminal; new certificate ACTIVE)
                                      │ revoke (§3.6) ──► REVOKED (terminal)
                                      │ expiry (face value) ──► EXPIRED (terminal for detection-as-current; §3.6)
   any presented certificate ──verify──► SEAL_VALID | BROKEN:<step> | SUPERSEDED | REVOKED | EXPIRED (§6.2)
```

- **3.1 No state is reachable by skipping a predecessor.** No detection exists against a non-`SEALED` certificate; no amendment exists without a prior certificate to supersede. Each transition appends to the certificate stream (§4.1); sealed fields never change (§2, L2).
- **3.2 States.** `SEALED` (transient, at registration) · `ACTIVE` · `SUPERSEDED` · `REVOKED` · `EXPIRED` (last three terminal). Verification verdicts (§6.2) are computed over a presented certificate, never stored as certificate state.
- **3.3 One active certificate per agent.** A second registration for the same `agent_ref` while one is `ACTIVE` is refused by name (§5.4) — the path is amendment (§3.4), not a parallel birth.
- **3.4 Amendment (hard case).** Any change to creator, model, config, or purpose scope = a **new certificate** citing the prior certificate's hash (`supersedes`), Herald-signed by the creator; the prior becomes `SUPERSEDED`. Detection against a superseded certificate still recomputes (history), labelled `certificate_status: superseded` on its face — an action must be judged against the certificate active *at the action's timestamp* (§3.5), which is why superseded certificates are retained, never deleted.
- **3.5 Detection semantics (hard case, normative).** For each presented action record: (a) select the certificate in the chain whose `[issued_at, superseded_at)` window contains the action's witnessed timestamp — an action outside every window is `INDETERMINATE:no-certificate-at-time`; (b) classify against that certificate's sealed scope (§4.3). Action types, counterparty classes, or resource classes the scope does not name are `INDETERMINATE:unmapped` — **never** defaulted to in- or out-of-purpose. Detection emits records; it changes no certificate state, blocks no action, and notifies no one in v0.1 (L3).
- **3.6 Revocation + expiry.** Revocation is a Herald-signed record (creator, or sponsor of record named in the certificate) appended to the stream: terminal, prospective-honest — the certificate verifies historically as sealed, and `REVOKED` for any claim of current standing, mirroring §6.2's split verdict. Expiry is the certificate's face `expires_at` passing: same split — history verifies, current standing does not. Neither rewrites the seal.

## 4. Data model + record formats

- **4.1 Canonical form + chaining.** Canonical JSON (sorted keys, no insignificant whitespace) per house pattern. `record_hash = sha256(canonical(record minus hash/signature fields) ‖ prev_hash)`; the certificate record's `prev_hash = sha256("eclipse-genesis/register" ‖ agent_ref)`. Amendment/revocation records chain onto the certificate they cite.
- **4.2 Certificate record.**

  | Field | Rule |
  |---|---|
  | `certificate_id` / `record_type` | `crt_` + 16 hex / `"genesis_certificate"` |
  | `agent_ref` | hash-form agent identifier (fixture in v0.1; Genesis mints the ref at registration and no other identity) |
  | `creator_ref` | hash-form creator identifier, as declared — sealed, not truth-checked (L4) |
  | `model_ref` / `config_hash` | model identifier as declared / sha256 of the canonical config as presented at registration |
  | `purpose_scope` | structured scope object (§4.3) — sealed; free-text purpose is presentational only and is **not** a detection input |
  | `purpose_text` | optional human-readable summary; unsigned-adjacent: carried outside the sealed canonical form, labelled `unsealed_summary` wherever rendered (§11.4) |
  | `issued_at` / `expires_at` | RFC 3339 UTC; expiry is a face value (§3.6) |
  | `supersedes` | prior `certificate_id` + its `record_hash`, or `null` for a first certificate |
  | `sponsor_ref` | optional sponsor of record (revocation authority, §3.6), or `absent` |
  | `prev_hash` / `record_hash` | per §4.1 |
  | `signatures` | `creator` (Herald, required) + `witness` counter-signature at registration (§4.4) |
  | `value_class` | `"test"` (§7) |

- **4.3 Purpose scope object (the detection surface — sealed).** `{action_types: [enum strings], counterparty_classes: [enum strings], resource_classes: [enum strings], max_value_class: "test"}` in v0.1 fixture vocabularies (§7.1). All four members required (an absent member is malformed, not "unlimited" — §5.4): a scope that constrains nothing cannot be sealed, because detection against it could never flag anything and the certificate would be decoration. The vocabularies are fixture enums in v0.1; extending them is a methodology-version change, not a registration-time choice.
- **4.4 Counter-signing.** The creator (Herald) signs first — the declarations are the creator's act. The witness counter-signs **at registration**, after §5.4 shape checks pass. The witness signature attests *sealing at a time*, never the truth of the declarations (L4, §11). No retrospective counter-signature exists; an imported, unwitnessed certificate is a downgraded artifact only (§6.4).
- **4.5 Detection record.** `record_type: "genesis_detection"`; `certificate_id` + `record_hash` of the certificate judged against (per action window, §3.5); `action_record_ref` + `action_record_hash` (the Docket/Meter record as presented — Genesis stores refs + hashes, never rewrites the source record); `action_ts`; `classification ∈ {IN_PURPOSE, OUT_OF_PURPOSE, INDETERMINATE}`; `clause` (the §4.3 member + value violated, present iff `OUT_OF_PURPOSE`); `reason` (present iff `INDETERMINATE`: `unmapped` | `no-certificate-at-time`); `detector_methodology_version`; `ts`; witness signature; `value_class: "test"`. Detection records chain among themselves per detector run (`run_id`), so a run's verdict set is itself recomputable as a set (§6.3).

## 5. MCP tool surface

Local stdio. One surface in v0.1 (Genesis holds no funds, blocks nothing, approves nothing); every tool is a pure function over presented fixtures + the local certificate store.

| Tool | Inputs | Outputs |
|---|---|---|
| `certificate_register` | `creator_ref`, `model_ref`, `config`, `purpose_scope` (§4.3), optional `sponsor_ref`, `expires_at`, Herald signature | sealed certificate (§4.2) or named refusal (§5.4) |
| `certificate_amend` | prior `certificate_id`, changed fields, Herald signature | new certificate citing `supersedes`; prior → `SUPERSEDED` (§3.4) |
| `certificate_revoke` | `certificate_id`, Herald signature (§3.6) | revocation record; certificate terminal |
| `certificate_get` | `certificate_id` | certificate + stream head + state (§3.2) |
| `certificate_verify` | presented certificate (+ amendment/revocation records), public keys | verification receipt (§6.2). Metering point (§9) |
| `purpose_detect` | presented certificate chain, presented action records (Docket/Meter grammar) | detection run: one §4.5 record per action + run receipt (§6.3). Metering point (§9) |
| `certificate_export` | `certificate_id` | full ordered record stream for the certificate family (the presentable artifacts) |

**Forbidden (do not exist):** any verb that edits a sealed field, un-seals, deletes a superseded/revoked certificate, blocks/suspends/penalises an action or agent, asserts a declaration is *true*, registers without a Herald creator signature, or counter-signs retrospectively. Absence is bench-checked by dispatch-table enumeration (§13).

- **5.4 Named refusals (checked in order; no state change on refusal).**

  | Code | Trigger |
  |---|---|
  | `CERTIFICATE_NOT_FOUND` | `certificate_id` unknown |
  | `DUPLICATE_ACTIVE_CERTIFICATE` | registration for an `agent_ref` with an `ACTIVE` certificate (§3.3) |
  | `SCOPE_INCOMPLETE` | any §4.3 member absent or empty — a scope constraining nothing cannot seal |
  | `SCOPE_VOCABULARY_UNKNOWN` | a scope value outside the fixture vocabularies (§4.3) — refused, never stored as a free string (an unmapped value would make every later detection `INDETERMINATE` by construction) |
  | `CONFIG_HASH_MISMATCH` | recomputed sha256 of the presented config ≠ the `config_hash` supplied (the seal binds the config presented, not a hash asserted about some other config) |
  | `HERALD_SIGNATURE_INVALID` | Herald verification of the creator signature fails, or key ref unknown |
  | `AMENDMENT_TARGET_INVALID` | amendment cites a certificate that is not the current `ACTIVE` head of its family (stale or already superseded) |
  | `ACTION_RECORD_MALFORMED` | a presented action record fails its own grammar's shape check (Docket/Meter, §12) — the run refuses the record by ref; other records in the run still classify |
  | `DETECTION_CERTIFICATE_BROKEN` | detection attempted against a certificate whose seal fails §6.2 — detection over a broken seal would launder it; refused whole |

## 6. Receipts / exports + downgrade semantics

- **6.1 Export shapes.** `certificate_export` (§5) — the certificate family stream; `certificate_verify` receipt (§6.2); `purpose_detect` run receipt (§6.3). No other export exists in v0.1.
- **6.2 Verification receipt + offline procedure (normative; artifacts + public keys only, no network, no Genesis state).** Receipt: `receipt_id`, `certificate_id`, `issued_at`, `seal_valid: true|false`, `verdict ∈ {SEAL_VALID, BROKEN, SUPERSEDED, REVOKED, EXPIRED}` (status verdicts compose with the seal check: a revoked certificate with an intact seal returns `REVOKED` with `seal_valid: true` — both facts on the face, neither swallowed), `first_failure: {step, code}` (iff `BROKEN`), sealed-field summary (creator/model/config hash/scope hash — hashes, not the declarations restated as fact), `value_class: "test"`; witness-signed (the creator does **not** sign the receipt). Procedure: (1) recompute `record_hash` + chain from §4.1; require `supersedes` linkage across the family. (2) Verify both signatures (creator Herald + witness). (3) Recompute `config_hash` from the presented config if presented; if no config is presented, the receipt states `config_body: not-presented` — the seal over the hash still verifies, the hash-to-body binding is simply unchecked and says so. (4) Apply status: amendment/revocation/expiry records as presented. Any step failing names its step; no partial "mostly sealed" verdict.
- **6.3 Detection run receipt.** `run_id`, `issued_at`, per-action §4.5 records (hash-chained), counts by classification, `certificate_hashes_judged` (one per window used, §3.5), `detector_methodology_version`, witness signature, `value_class: "test"`. Recompute: re-run classification from (certificates, action records) alone and require an identical record set — classification is a deterministic function of the sealed scope + the action record's own fields; any action field not in the source grammar is not a classification input.
- **6.4 Downgrade law (normative).** A certificate that fails §6.2 at any step exports only as `DOWNGRADED_CERTIFICATE_EXPORT` — unsigned summary, `verified: false`, `verdict: BROKEN:<step>` on its face. A detection run over a broken certificate is never issued (§5.4). **No artifact is ever upgraded post-hoc:** a corrected registration is a *new* certificate (via §3.4 where a family exists); earlier receipts are never amended or withdrawn in place.

## 7. Fixture discipline + config fence

- **7.1 Fixtures.** All registrations are fixture agents: fixture creators, fixture model refs, fixture configs, fixture Herald keys. Scope vocabularies are pinned fixture enums: `action_types` (e.g. `read`, `write`, `transact-fixture`, `message`, `delegate`), `counterparty_classes` (e.g. `public`, `allowlisted`, `auditor`), `resource_classes` (e.g. `fixture-data`, `fixture-compute`, `fixture-funds-test`). Action records are fixture Docket/Meter-grammar records (§12) with deterministic ids under a seed.
- **7.2 value_class.** Every artifact — certificate, detection record, receipt, export, refusal entry — carries `value_class: "test"`.
- **7.3 Fail-closed fence.** Startup refuses (hard exit, `CONFIG_FENCE_REFUSED:<class>`) on: any live-registry URL / non-local endpoint; any non-fixture creator/agent source; `value_class ≠ "test"`; any key material outside local fixture `keys/` (chmod 600, gitignored). **No network call, no live registration, no action interception exists in v0.1 code** — absence is bench-grepped (§13), not merely unused.
- **7.4 Keys.** Creator + witness keys are locally generated fixture keys consumed **through Herald's signing interface** (§12); Genesis stores key *refs* in certificates, never private key material in any artifact.

## 8. Bench fixtures enumerated

House style (unittest, deterministic, socket-denied). All artifacts `value_class: "test"`.

**Happy path**
- **F-G1 Register + verify:** register (creator C, model M, config, scope: `read`/`write` on `fixture-data` for `allowlisted`) → §6.2 verify → `SEAL_VALID`, `seal_valid: true`.
- **F-G2 In-purpose detection:** action records: `read` + `write` on `fixture-data`, counterparty `allowlisted`, inside the certificate window → both `IN_PURPOSE`; run receipt recomputes identically (§6.3).
- **F-G3 Zero-action run:** detection over an empty action set → run receipt with zero records, counts all zero — a valid run, not an error.

**Scope + detection battery**
- **F-G4 Out-of-purpose by action type:** action `transact-fixture` against the F-G1 scope → `OUT_OF_PURPOSE` naming clause `action_types`.
- **F-G5 Out-of-purpose by counterparty + resource:** `read` for counterparty `public` → `OUT_OF_PURPOSE:counterparty_classes`; `write` on `fixture-funds-test` → `OUT_OF_PURPOSE:resource_classes`. Each record names exactly its clause.
- **F-G6 Indeterminate, never coerced:** action with a type outside the fixture vocabulary → `INDETERMINATE:unmapped`; action timestamped before registration → `INDETERMINATE:no-certificate-at-time`. Neither is counted as in- or out-of-purpose anywhere in the run receipt.
- **F-G7 Detection does not block:** the F-G4 run completes, the action record is unchanged (hash diffed before/after), the certificate remains `ACTIVE`, and dispatch enumeration confirms no blocking verb exists to call (§5, §13).
- **F-G8 Incomplete scope:** registration missing `resource_classes` → `SCOPE_INCOMPLETE`; scope with an out-of-vocabulary value → `SCOPE_VOCABULARY_UNKNOWN`; config whose hash ≠ supplied `config_hash` → `CONFIG_HASH_MISMATCH`. No certificate exists after any of them.

**Lifecycle battery**
- **F-G9 Amendment + windowed detection:** register scope v1 → amend widening `action_types` to include `message` → prior `SUPERSEDED`. A `message` action timestamped *before* the amendment → judged against v1 → `OUT_OF_PURPOSE`; the same action *after* → `IN_PURPOSE`. Both judgments cite the certificate hash they used (§3.5).
- **F-G10 Duplicate + stale amendment:** second registration for the same agent while `ACTIVE` → `DUPLICATE_ACTIVE_CERTIFICATE`; amendment citing the superseded (non-head) certificate → `AMENDMENT_TARGET_INVALID`.
- **F-G11 Revocation + expiry:** (a) revoke → verify → `REVOKED` with `seal_valid: true`; detection for a pre-revocation action still recomputes, labelled historical. (b) Certificate past `expires_at` → verify → `EXPIRED` with `seal_valid: true`.

**Tamper battery**
- **F-G12** Flip one scope value in a presented certificate → chain recompute fails at §6.2 step 1, named; detection against it → `DETECTION_CERTIFICATE_BROKEN`. Flip `creator_ref` → step 1 fails. Remove the witness counter-signature → step 2 fails. Reorder family records → step 1 fails.

**N-check — the decisive fixture**
- **F-G13 THE defining test (§2.3):** a certificate sealed through fixture registration is exported alone; a presented set of witnessed fixture action records (Docket/Meter grammar) contains three in-purpose actions, one `OUT_OF_PURPOSE` action, and one `INDETERMINATE:unmapped` action. In a fresh process with no Genesis state, from export + action records + public keys alone: §6.2 recompute proves the seal, and §6.3 recompute reproduces the exact classification of all five actions, naming the violated clause for the out-of-purpose one. Any step requiring Genesis's store, and any classification that blocks, alters, or deletes the out-of-purpose action record, fails the bench.

**Fence battery**
- **F-G14** §7.3 configs → startup refused with the same codes; tree grep finds no HTTP/registry client, no interception hook, no non-fixture endpoint string outside the fence table + negating docs; §6.4 downgrade: imported certificate with no witness counter-signature → only `DOWNGRADED_CERTIFICATE_EXPORT` issuable, no upgrade path.

## 9. Pricing hooks

- **9.1 Metering points only.** Two metered event classes, at the Argus 101 lines for this product: registration — **FREE** (a zero-value Meter record is still emitted, so the funnel is counted, not invisible); verification-class issuances (`certificate_verify` receipts + `purpose_detect` run receipts) — **$0.05/verification** (price book governs figures at ship time; this spec invents no other charge).
- **9.2** **v0.1 implements no charge path, no payment call, and no entitlement check** — metering records only (count + `certificate_id` + event class), emitted in Meter grammar for later ingest, behind the house's existing pricing gates. Free registration is never gated on a payment instrument existing.

## 10. Counsel gate

- **10.1 v0.1 needs no new counsel clearance** — local, fixture-only, no live agent or creator data, no claim beyond §11 wording. No gate is pre-built around.
- **10.2 The gate (later phase, named).** Any live phase — a real registry accepting real registrations, certificates presented to third parties for reliance, detection records used in disputes, enforcement, or platform decisions, or any "registered agent" claim towards regulated buyers — requires counsel review **before build** of: (a) registration/reliance claim language (§11 wording as the submission), (b) what a sealed *declaration* does and does not warrant, and liability when a counterparty relies on it, (c) creator-identity data posture if any creator maps to a natural person or real organisation, (d) retention/takedown posture for certificates of agents later found harmful. Live mode is a post-gate, re-benched code change, not a config flip; v0.1 contains no dormant live path.

## 11. Honest-label rules

- **11.1** Claims are **verdict + scope only**: `Eclipse Genesis — <VERDICT>(local/fixture)` once benched; before bench: "bench pending — no certification is claimed."
- **11.2** Permitted claim, exact sense only: "creator, model, config hash, and declared purpose scope **as declared and sealed at registration**, recomputable from the certificate." Never "verified agent," "approved agent," "licensed," "trusted," "safe," or any wording converting a sealed declaration into a truth finding or an endorsement (L4). Genesis seals what was said; it does not vouch for who said it or whether it was true.
- **11.3** A detection verdict is stated as "**detectable** against the sealed scope from the presented records" — never "the agent violated its purpose" as an adjudicated fact: classification is over presented records against declared scope (§3.5), records may be incomplete, and `INDETERMINATE` is a standing possibility that no surface may silently drop from a run summary. Historical (superseded/revoked/expired-window) judgments are never presented as current standing (§3.4–§3.6).
- **11.4** `purpose_text` is rendered only with its `unsealed_summary` label (§4.2); the sealed structured scope (§4.3) is the only detection input and the only scope any surface may quote as sealed. Every listing states the v0.1 scope on its face: local stdio, fixture agents/creators/keys, no live registry, detects-never-blocks.

## 12. Boundaries + dependencies

| Product | Boundary |
|---|---|
| **Herald** | **Dependency — signing.** Herald provides signing/verification (creator signatures + witness counter-signatures, key refs). Genesis **consumes Herald and does not redefine signing**: no signature scheme, canonical-signing rule, or key-custody rule is specified here; "Herald-signed" means whatever Herald's current benched interface verifies. A Herald shape gap is a build-stage blocker (§14), not a licence to invent a local scheme. |
| **Docket / Meter** | **Dependencies — action records (consumed, never redefined).** Detection inputs are witnessed action records *in Docket's / Meter's own grammars*, presented to Genesis; Genesis reads the fields those grammars define (actor, action type, counterparty, resource, timestamp, value class), stores only refs + hashes (§4.5), and never redefines, re-emits, or mutates a source record. If a needed field is absent from both grammars, detection over that dimension is `INDETERMINATE:unmapped` — the gap is surfaced (§14), not papered over with a Genesis-side record format. v0.1 fixtures are fixture records in those grammars; no live Docket/Meter call is made or claimed. Meter also receives Genesis's own §9 usage records — emitted in Meter grammar, no live ingest claimed. |
| **Continuity (#14)** | Sibling. Continuity's genesis *link* may cite a Genesis `certificate_id` in a future composition; Continuity starts from an identified principal and Genesis ends at a sealed birth record. v0.1: no coupling, no shared records. |
| **Doppel (#16) / Alias (#18)** | Siblings, disjoint mechanisms (§1.3). Doppel may cite a Genesis certificate as its enrolled identity's ref in future; Alias principals may hold certificates in future. Neither is a v0.1 dependency. |
| **Registry / Bazaar catalog** | Genesis v0.1 is not the registry and writes no catalog (spec-only task constraint). Fixture `agent_ref`s are local strings with no registry meaning. |

## 13. Bench criteria

- **B-G1** §8 fixtures F-G1…F-G14 pass as enumerated, deterministically, socket-denied, on a clean checkout.
- **B-G2 The novel mechanism is what is verified** (§2.1): F-G13 passes with seal + all five classifications recomputed in a fresh process from export + presented records + public keys alone.
- **B-G3** State machine (§3): fuzzed call sequences produce only legal transitions or named refusals (§5.4); every §5.4 code is reachable by its fixture and no refusal mutates the certificate stream (head/seq diffed before/after).
- **B-G4** Detects-never-blocks (L3): dispatch-table enumeration shows no blocking/enforcement verb; F-G7's before/after hashes prove detection mutates neither action records nor certificate state.
- **B-G5** Window correctness (§3.5): F-G9's split judgment (same action type, different windows, opposite verdicts, each citing its certificate) passes; an implementation judging all actions against the latest certificate fails the bench.
- **B-G6** Indeterminate honesty: across all fixtures, no `INDETERMINATE` action is counted, summarised, or exported as either in- or out-of-purpose (§11.3).
- **B-G7** Downgrade (§6.4): broken/unwitnessed artifacts export downgraded only; grep + fixture prove no upgrade path exists.
- **B-G8** Fence + absence greps (§7.3, F-G14) clean; `value_class: "test"` on 100% of emitted artifacts.
- **B-G9** Honest labels (§11) verbatim in README/manifest; forbidden claim strings ("verified agent", "approved agent", "licensed") absent tree-wide; `purpose_text` never rendered without its unsealed label (fixture-sampled).
- **B-G10** Consumption discipline (§12): tree grep finds no Genesis-defined signature scheme and no Genesis-defined action-record schema; all signing routes through the Herald stub, all action inputs parse through the Docket/Meter grammar fixtures.

## 14. Open questions for build stage

- **Q-G1** Docket/Meter field coverage: do the current Docket and Meter record grammars both carry counterparty class + resource class as first-class fields? §4.5/§3.5 assume the union is readable; any dimension missing from both grammars stays `INDETERMINATE:unmapped` in v0.1 (§12) — build inventories the fields and reports gaps, it does not extend either grammar from inside Genesis.
- **Q-G2** Scope vocabulary governance: the §7.1 fixture enums are v0.1-pinned — who owns adding a value in a later phase, and is a vocabulary extension a methodology-version bump (assumed) or a certificate-family break? Ruling needed before any live phase; v0.1 fixtures do not exercise extension.
- **Q-G3** Amendment authority on creator-key loss: amendment/revocation require the creator's Herald signature; a lost key strands the family as `ACTIVE`-forever (expiry aside). No recovery path is spec'd — deliberately (an invented recovery signer would be a second creator). Flag for counsel phase (§10.2), not for build improvisation.
- **Q-G4** Config presentation at verify (§6.2 step 3): fixtures present the config body (assumed); build confirms the `not-presented` branch is exercised by at least one fixture so the receipt's unchecked-binding label is bench-proven, not theoretical.
- **Q-G5** Sponsor of record: Genesis carries `sponsor_ref` for revocation authority (§3.6) but defines no sponsor relationship — confirm at build that no fixture implies Genesis adjudicates sponsorship disputes.

---

*A Cyan Eclipse Technologies product. The "Powered by Cyan Eclipse Technologies" attribution travels with it. Source line: `argus-101-20261027.md` #17.*
