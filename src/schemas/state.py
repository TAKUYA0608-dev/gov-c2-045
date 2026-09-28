"""GOV-C2-045 — Agent state (Municipal Public-Records Disclosure Redaction Review, Cat 2).

ADR-005: State is a flat TypedDict — never a validation/BaseModel instance. Complex fields are stored
as JSON strings (``NotRequired[str]`` + ``# JSON:``); nodes ``json.dumps`` on write / ``json.loads`` on
read.

Advisory-only (read-only): the agent never alters or publishes a public record and never *finalises* a
redaction or disclosure decision — it only proposes redaction candidates with exemption rationale for an
authorized official to confirm (mandatory HumanGate). Supplied metadata / identifier fields are
credential- and PII-redacted on the input side (S-1) before they persist to State; personal information
in the record content is additionally redacted in the output packet (S-3) as defense-in-depth so raw PII
values are not reproduced in the review packet itself. No raw PII persists beyond the authorized record
`content` under review.

All agent-specific fields are NotRequired (populated progressively; absent at empty-start invoke).
"""

from __future__ import annotations


from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Agent state for the disclosure redaction-review workflow."""

    # ── pre_process (RequestValidate — S-1 normalize + S-2 access-scope gate) ─────
    validated_input: str  # JSON: {request:{...}, records:[...], policy_hint}
    input_format: str  # "json" | "text" | "empty"
    enriched_context: str  # JSON: {source, channel} (read-only caller context)

    # ── inner workflow (inventory → policy-flag → synthesize → human-gate) ───────
    record_inventory: str  # JSON: [{record_id, title, record_type, exemption_rulesets[]}]
    record_count: int  # authorized records inventoried (0 → out-of-scope safe answer)
    redaction_candidates: str  # JSON: [{record_id, field, exemption_category, rationale, confidence}]
    review_packet: str  # JSON: composed packet body (candidates + rationale + citations)
    human_review: str  # JSON: {items[], human_review_status, exceptions}
    result: str  # JSON: assembled Disclosure Review Packet report

    # ── post_process (PacketCompose — S-3 sanitize/redact/citation + S-4 audit) ──
    formatted_output: str  # JSON: final envelope (packet + DRAFT disclaimer)
    disclaimer: str  # mandatory DRAFT / advisory disclaimer (final decision = human)
    audit_logged: bool  # True once the terminal audit event is emitted

    # ── degraded-path signalling (SUCCESS + error_code, never status=ERROR) ──────
    error_code: str  # INJECTION_REJECTED | INPUT_REJECTED | INPUT_TOO_LONG | UNAUTHORIZED_RECORDS | NO_RECORDS
    error_message: str  # operator-facing detail
