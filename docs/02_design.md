# Template Design Specification — GOV-C2-045

Municipal Public-Records Disclosure Redaction Review Packet Agent (Cat 2).

## Position in AgentCore Architecture

- **Agent Class**: `MunicipalPublicRecordsDisclosureRedactionPacketAgent` (module-level alias of `Graph`)
- **L1 Base**: **AgentBaseGraph** (Cat 2 — outer 5-node backbone; direct L1 inheritance, no L2)
- **Category**: Cat 2 — a multi-step domain workflow (validate → inventory/classify → policy-flag →
  packet-synthesize → human-gate → compose) producing a traceable **Disclosure Review Packet**; GOV industry
- **Three-Layer Separation**: State = flat TypedDict; Node = L1 inheritance (`execute` override only);
  Graph = outer `AgentBaseGraph` + **`GraphNode` in the `main` slot** wrapping an inner `BaseGraph`

## Architecture Overview

Cat 2 pattern — the `main` slot is a **`GraphNode`** (`DisclosureReviewWorkflowGraphNode`, **subgraph
cached**) that wraps the inner `DisclosureReviewWorkflow` (`BaseGraph`). Inner graph is a **static linear
backbone with per-node skip guards** (conditional edges do not propagate across the subgraph boundary).

**Advisory-only (read-only):** the agent never alters or publishes a public record and never *finalises* a
redaction or disclosure decision. It proposes **redaction candidates** with exemption rationale for an
authorized official to confirm via a **mandatory HumanGate**. Personal information is **redacted in the
output packet (S-3)** so the packet itself does not reproduce raw PII values.

### Node Configuration

| Node | Responsibility | Input State | Output State | Inherits/Overrides |
|------|---------------|-------------|--------------|-------------------|
| initialize | schema_version, session_id, trust_level | user_input | (framework) | InitializeNode (default) |
| pre_process | `RequestValidateNode` — S-1 normalize + S-2 access-scope gate (degrade prompt-injection / non-authorized / oversize records to a discarded-body SUCCESS + error_code); parse disclosure request + records | user_input | validated_input, input_format, enriched_context, error_code | FunctionNode.execute |
| main | `DisclosureReviewWorkflowGraphNode` (GraphNode) → inner workflow | validated_input | result, record_count | GraphNode |
| post_process | `PacketComposeNode` — S-3 output sanitize + PII redaction + citation completeness + DRAFT disclaimer + S-4 audit | result | formatted_output, disclaimer, audit_logged | FunctionNode.execute |
| finalize | response_metadata, total_time_ms | | (framework) | FinalizeNode (default) |

**Inner workflow (`DisclosureReviewWorkflow` : BaseGraph):**

```
START → record_inventory_classify → policy_flag → review_packet_synthesize → human_gate → END
```

| Inner node | Responsibility |
|---|---|
| RecordInventoryClassify | **deterministic** — inventory authorized records + route each to applicable non-disclosure exemption rulesets; 0 records → out-of-scope safe answer |
| PolicyFlag | flag sensitive fields (personal / non-disclosure exemptions) as **redaction candidates** with exemption category + rationale + confidence (candidate only — never finalised) |
| ReviewPacketSynthesize | compose redaction candidates + rationale + exemption citations + exceptions into a traceable review packet |
| HumanGate | **deterministic gate** — mark all candidates / low-confidence items for authorized human review; record `human_review_status` + exceptions (finalisation by staff only) |

### Data Flow

```
START → initialize → pre_process → main(GraphNode → inner linear workflow) → post_process → finalize → END
                                     ↓ (retry, max 3)
                                   pre_process
```

All rejects (**prompt-injection** / empty / oversize / non-authorized access) are **degraded, never
`status=ERROR`**: `execute()` discards the rejected body (`validated_input="{}"`), returns **SUCCESS +
`error_code`** (`INJECTION_REJECTED` / `INPUT_REJECTED` / `INPUT_TOO_LONG` / `UNAUTHORIZED_RECORDS`), and
the inner 0-record branch produces the out-of-scope safe answer. A prompt-injection / non-authorized record
is therefore **never processed into a review packet**, yet post_process **S-3** (redaction / DRAFT
disclaimer) and **S-4** (terminal audit — counts only, no record content) **always run**. `status=ERROR` is
deliberately avoided because it short-circuits `__call__` so `route()` goes straight to `finalize`, skipping
main / post_process. Empty / 0-record input follows the same degraded path; policy_flag /
human_gate no-op (with a count-only S-4 skip event) and review_packet_synthesize emits the out-of-scope safe
answer — no fabricated candidates.

### State Definition

| Field | Type | Purpose |
|-------|------|---------|
| validated_input | str (JSON) | `{request, records, policy_hint}` |
| record_inventory / record_count | str/int | classified inventory / 0 → out-of-scope safe answer |
| redaction_candidates | str (JSON) | `[{record_id, field, exemption_category, rationale, confidence}]` |
| review_packet / human_review | str (JSON) | composed packet body / `{items[], human_review_status, exceptions}` |
| result / formatted_output | str (JSON) | inner report / final envelope |
| disclaimer / audit_logged | str/bool | mandatory DRAFT disclaimer + terminal audit |
| error_code / error_message | str | degraded path — `INJECTION_REJECTED` / `INPUT_REJECTED` / `INPUT_TOO_LONG` / `UNAUTHORIZED_RECORDS` / `NO_RECORDS` (SUCCESS + error_code, never status=ERROR) |

**State Constraints:** flat TypedDict; JSON strings for complex fields (ADR-005); no raw PII persisted
beyond the authorized record `content` under review — supplied metadata / identifier fields are
S-1 hygiene-redacted (credential + PII) before persist; `enriched_context` is a JSON string.

**Platform masking (S-2).** The platform's personal-data pass runs before every node and replaces My Number
/ e-mail / phone values, labelled names (label included) and runs of two or more Title-Case words with
`[MASKED]`; it cannot be switched off, so the PII regexes never see those values. Rule: every `[MASKED]` span
in a record's content becomes a `personal_info` candidate with confidence 0.65 (deliberately below the
HumanGate 0.7 line, so it is listed in the low-confidence exceptions) and the candidate field
`limitation: "PERSONAL_DATA_MASKED"`. The packet and the envelope carry `limitations: ["PERSONAL_DATA_MASKED"]`
(codes only); `message` explains how many spans were masked and that the original must be checked. Evidence
snippets widen their window to whole personal-data matches before redaction, so a value crossing the window
edge is never shown in part. Records without masked text return the previous output plus `limitations: []`.

## Security Design (S-1 → S-5)

- [x] **GraphNode-in-main** (Cat 2 composition, criterion #9) — `error_strategy="propagate"`,
  `propagate_hitl=False`, **subgraph cached**
- [x] S-1 `required_trust_level=VERIFIED_EXTERNAL` on all FunctionNode subclasses + agent-level.
  **Field-level input hygiene**: every supplied *metadata / identifier* field written to
  `validated_input` (`record_id` / `title` / `provenance`, the `request` dict, `policy_hint`) is routed
  through `hygiene_metadata()` (control-char strip + credential-token + PII redaction, recursive over
  nested dict/list) so no raw credential or PII persists to State beyond the authorized record `content`
  under review. Record `content` (the payload being reviewed) keeps PII for candidate flagging but has
  control chars + credential tokens stripped (`hygiene_content()`).
- [x] S-2 `_extra_security_gate_input()` (pre) — **no-op domain hook (returns state unchanged, never
  raises; SDK 1.0.0)**. Prompt-injection markers + access-scope authorization + size cap are enforced in
  `execute()`: **prompt-injection**, records lacking authorization/provenance, or oversize input are all
  **degraded to SUCCESS + `error_code` with the body discarded (`validated_input="{}"`)**, never a
  `status=ERROR` short-circuit (so main / post_process S-3/S-4 always run). **Injection is
  rejected at this execute() level** (`INJECTION_REJECTED`) — the untrusted body is never processed. The
  S-3 output gate additionally
  **neutralizes** injection markers as **defense-in-depth** for anything that reaches the composed packet.
- [x] S-3 `_extra_security_gate_output()` (post) — mandatory-disclaimer preservation; **may raise** (SDK 1.0.0).
  execute() also redacts personal information (My-Number / phone / email / address) and neutralizes injection
  markers in the composed packet, and verifies citation completeness.
- [x] S-4 `emit_trace_event()` in every `execute()` (record type / counts / exemption categories only —
  no raw PII); terminal audit always fires
- [x] S-5 credential CI scan (`gate-credential-scan`) — no secrets in `src/`

## Import Isolation Confirmation
- [x] No `agenticstar` SDK (Level 0) import — PB-4
- [x] Import targets: `framework/`, `langgraph`, and `src.` only

## Design Decision Record

| Decision | Chosen | Rationale |
|----------|--------|-----------|
| L1 base type | AgentBaseGraph | Fixed pipeline, no autonomous loop |
| Composition | **GraphNode-in-main + inner BaseGraph (cached)** | Cat 2 multi-step domain workflow |
| Inner topology | **Linear + per-node skip guards** | Conditional edges don't propagate across the subgraph boundary |
| Redaction candidates | **Deterministic taxonomy + PII regex** | Auditable exemption flagging; fixed-template rationale phrasing — **no LLM** (no model in `config/agent.yaml`, no LLM dependency in `pyproject.toml`) |
| HumanGate | **Mandatory, deterministic gate** | Agent proposes only; authorized staff finalise redaction / disclosure |
| Record handling | **Advisory-only, read-only** | Never alters or publishes a public record |
| PII / credentials in State | **S-1 field hygiene on supplied metadata + S-3 output redaction** | Metadata/identifier fields redacted before persist; record content keeps PII for flagging, output packet redacted at S-3 — packet identifies where/why to redact without reproducing raw PII |
| Rejection signalling | **SUCCESS + error_code, body discarded** (`validated_input="{}"`) | A prompt-injection / non-authorized / oversize record is never processed into a packet, yet post_process S-3/S-4 always run (no ERROR short-circuit — SDK 1.0.0) |
| Injection handling | **Rejected at execute() (`INJECTION_REJECTED`) + S-3 neutralization** | Execute-level rejection is required; S-3 marker neutralization remains as defense-in-depth |

## Open Items (Stage ③ implementation MR)
- Node implementations + inner workflow graph (shipped in the implementation MR).
- Seeded `DisclosurePolicyKB` — non-disclosure exemption taxonomy (personal info / corporate info /
  deliberation / administrative operations / public safety) + PII regex.
- Unit + integration + PB tests; coverage ≥ 89%.
