# Test Specification — GOV-C2-045

## Test Strategy
- Coverage target: **89%+** (achieved 94%, `--cov=src`)
- Test types: Unit (pre/post + inner nodes + services) / Unit (Cat 2 graph wiring) / Integration / Proof-of-Boundary

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State contract: flat TypedDict | `State(AgentState)`, NotRequired primitives + JSON strings | ✅ PASS |
| TC-02 | S-2 hook is no-op (never raises); rejects degrade in execute() | `_extra_security_gate_input` returns state unchanged; injection/oversize/non-authorized → SUCCESS + error_code, body discarded, post_process runs | ✅ PASS |
| TC-03 | No JWT/Credential in `src/` | `gate-credential-scan`: 0 violations | ✅ PASS |
| TC-05 | S-4: domain events only (no duplicate lifecycle events) | only domain events emitted | ✅ PASS |
| TC-06 | S-2 `_security_gate_input()` not overridden | `@final`; only `_extra_*` extended | ✅ PASS |
| TC-07 | S-3 `_security_gate_output()` not overridden | `@final`; may raise via `_extra_*` | ✅ PASS |
| TC-08 | `required_trust_level` enforced | VERIFIED_EXTERNAL on all nodes (`gate-trust-level-check`) | ✅ PASS |
| TC-11 | S-4: ≥1 domain `emit_trace_event()` per `execute()` | emitted on every path | ✅ PASS |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Expected Result | Result |
|-------|----------|----------------|--------|
| PB-1 | `emit_trace_event()` fires from `shared.utils.audit_logger` | No silent failures | ✅ (real SDK on CI) |
| PB-2 | Post-invoke State is primitives only | No Pydantic/dataclass | ✅ PASS |
| PB-4 | Import isolation — no Level 0 imports | AST scan: 0 violations | ✅ PASS |
| PB-6 | Invoke order S-1 → S-4 → S-2 → execute → S-3 → S-4 | Order verified | ✅ (real SDK on CI; local-stub env-diff) |
| PB-7 | (conditional — hitl.enabled) interrupt() propagation | SKIPPED (hitl not enabled) | ⏭ conditional stub |
| Composition | Cat 2 `GraphNode`-in-main wraps inner `BaseGraph` (cached) | gate-composition passes | ✅ (S-0 gate) |

## Business Logic Tests

| BL-ID | Test | Input | Expected Result | Result |
|-------|------|-------|----------------|--------|
| BL-01 | Personal-info flagging | record with 氏名/住所/My-Number/email | personal_info candidates + rationale | ✅ PASS |
| BL-02 | Exemption flagging | record with 審議中 / 取引先・見積・原価 | corporate_info + deliberation candidates | ✅ PASS |
| BL-03 | Review packet synthesis | ≥1 classified record | traceable packet + exemption citations | ✅ PASS |
| BL-04 | HumanGate mandatory | any candidates | `human_review_status=pending_human_review` + exceptions | ✅ PASS |
| BL-05 | Out-of-scope | request with no attached records | `out_of_scope`, no citations | ✅ PASS |
| BL-06 | Empty input | "   " | degraded SUCCESS, still audits | ✅ PASS |
| BL-07 | Access-scope gate | record `authorized: false` | degraded SUCCESS + `error_code=UNAUTHORIZED_RECORDS`, body discarded, out-of-scope safe answer + disclaimer + audit (real `Graph().invoke()`) | ✅ PASS |
| BL-08 | Injection rejected at input (execute-level degraded) | record content with injection markers | degraded SUCCESS + `error_code=INJECTION_REJECTED`, body discarded, out-of-scope safe answer + disclaimer + audit (S-3 neutralization is defense-in-depth) | ✅ PASS |
| BL-09 | S-3 PII redaction | packet containing raw My-Number/email | raw PII absent from `formatted_output` | ✅ PASS |
| BL-10 | Mandatory DRAFT disclaimer | any packet | S-3 gate blocks output missing it | ✅ PASS |
| BL-11 | Oversize input | `> _MAX_INPUT` chars | degraded SUCCESS + `error_code=INPUT_TOO_LONG`, body discarded, out-of-scope + disclaimer + audit; canary absent from output | ✅ PASS |
| BL-12 | Terminal safety via real `Graph().invoke()` | injection / unauthorized / oversize request | reaches post_process (`PacketComposeNode` in `node_history`), `status=SUCCESS`, out-of-scope envelope + `_DISCLAIMER`, no record content/PII/injection markers in output | ✅ PASS |
| BL-13 | S-1 field-level hygiene | credential / PII in supplied metadata fields (record_id / title / provenance / request / policy_hint) | credential + PII redacted before persist → absent from `validated_input` **and** the output packet; record `content` keeps PII (for flagging) but drops credentials | ✅ PASS |

## Test Execution Summary
- Total: 61 (unit 42 [incl. server import] + integration 14 + proof_of_boundary 5)
- Local (the local SDK stub): **57 passed · 3 skipped** (server import + PB-7 conditional ×2 — hitl not enabled) ·
  1 env-diff: `test_pb_invoke_order` monkeypatches `base_node.emit_trace_event` (absent in the local SDK stub;
  present in the real SDK → passes on CI, same as reference a sibling template)
- Coverage: **94%** (`--cov=src`)
- S-1 field-level hygiene (BL-13): `tests/unit/test_nodes.py` `TestS1FieldHygiene`
  (metadata/identifier credential+PII redaction; content keeps PII / drops credentials; recursion;
  control-char strip) + `tests/integration/test_end_to_end.py` `TestS1FieldHygieneEndToEnd`
  (metadata secrets absent from `validated_input` and the output packet, end-to-end)
- Real `Graph().invoke()` degraded-path proof: `tests/integration/test_end_to_end.py`
  `TestGraphInvoke` (**injection** / unauthorized / oversize reach post_process → out-of-scope + DRAFT
  disclaimer, no rejected record content / PII / injection markers in output; full authorized records →
  review_packet) + `TestDegradedNodeChain` (`error_code` incl. `INJECTION_REJECTED` + audit_logged +
  discarded body)
