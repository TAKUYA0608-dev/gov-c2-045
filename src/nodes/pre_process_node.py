"""GOV-C2-045 — pre_process node: RequestValidate (S-1 normalize + S-2 access-scope gate).

Accepts a structured disclosure request `{request, records, policy_hint}` (or a plain NL request with no
attached records), normalizes it (NFKC), and enforces the S-2 access-scope gate: records must be
authorized (the caller vouches for provenance/access).

All rejects (**prompt-injection** / empty / oversize / non-authorized records) return
`status=SUCCESS + error_code` (degraded). The rejected body is **discarded** (`validated_input="{}"`) so no
record content / PII / instruction-like text is ever processed into a review packet; the request flows
through the inner 0-record branch to the out-of-scope safe answer so post_process S-3 (redaction /
disclaimer) and S-4 (terminal audit) **always run**. A `status=ERROR` short-circuit is deliberately NOT
used: ERROR short-circuits `__call__`, so the framework `route()` sends the request straight to `finalize`
and main / post_process (disclaimer / redaction / audit) never run.

**Injection is rejected at this execute() level** (a degraded `INJECTION_REJECTED` path): the untrusted
body is never processed. The S-3 output
gate additionally **neutralizes** injection markers as defense-in-depth for anything that reaches the
composed packet.

**S-1 field-level hygiene**: every *supplied metadata / identifier*
field that persists to `validated_input` — `record_id` / `title` / `provenance`, the `request` dict, and
`policy_hint` — is routed through `hygiene_metadata()` (control-char strip + credential-token + PII
redaction), so no raw credential or personal information is written to State for anything other than the
authorized record `content` under review. `content` (the payload being reviewed) keeps PII so the
deterministic scan can flag it, but has control chars + credential tokens stripped (`hygiene_content()`);
the composed packet is fully PII-redacted at S-3.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import hygiene_content, hygiene_metadata
from src.utils.audit import emit_trace_event

_AGENT_NAME = "MunicipalPublicRecordsDisclosureRedactionPacketAgent"
_MAX_INPUT = 50_000  # disclosure packets carry several records — larger cap than a Q&A agent
_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "disregard the above",
    "system prompt",
    "you are now",
    "###system",
    "<|im_start|>",
)


def _nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text or "")


def _parse_records(raw: str) -> list[dict[str, Any]] | None:
    """Best-effort: return the records list if *raw* is a structured request, else None."""
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if isinstance(obj, dict) and isinstance(obj.get("records"), list):
        return [r for r in obj["records"] if isinstance(r, dict)]
    return None


class RequestValidateNode(FunctionNode):
    """Validate the disclosure request and extract {request, records, policy_hint}."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-2 domain hook — no hard reject (SDK 1.0.0 contract: MUST NOT raise).

        Prompt-injection / oversize / non-authorized-record rejection is all handled as a degraded
        `status=SUCCESS + error_code` path in `execute()` (the untrusted body is discarded and never
        processed) so main / post_process S-3/S-4 always run. A `status=ERROR` here would short-circuit
        `__call__` and skip main / post_process. The framework default S-2 input
        handling still applies. Returns state unchanged.
        """
        return dict(state)

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        raw = state.get("user_input", "") or ""
        input_context = state.get("input_context", {})  # read-only [C1]
        enriched = json.dumps(
            {"source": _AGENT_NAME, "channel": input_context.get("channel", "unknown")},
            ensure_ascii=False,
        )

        normalized = _nfkc(raw).strip()

        # ── degraded rejections — discard the body (validated_input="{}"), never status=ERROR ──
        # ERROR short-circuits __call__ so main / post_process (disclaimer / redaction / S-4 audit)
        # would be skipped. The audit event carries counts only — no record content.

        # Prompt-injection markers -> degraded SUCCESS + error_code (body discarded, never processed).
        # Execute-level rejection is required; the
        # untrusted body never reaches the inner workflow. S-3 marker neutralization stays as
        # defense-in-depth for anything that slips through.
        if any(marker in normalized.lower() for marker in _INJECTION_MARKERS):
            emit_trace_event("request_validate.rejected", {"reason": "prompt_injection"}, state)
            return {
                "validated_input": "{}",
                "input_format": "rejected",
                "enriched_context": enriched,
                "error_code": "INJECTION_REJECTED",
                "error_message": "prompt-injection marker detected; input not processed",
                "status": AgentStatus.SUCCESS.value,
            }

        if not raw.strip():
            emit_trace_event("request_validate.rejected", {"reason": "empty_input"}, state)
            return {
                "validated_input": "{}",
                "input_format": "empty",
                "enriched_context": enriched,
                "error_code": "INPUT_REJECTED",
                "error_message": "no disclosure request submitted",
                "status": AgentStatus.SUCCESS.value,
            }

        if len(raw) > _MAX_INPUT:
            emit_trace_event("request_validate.rejected", {"reason": "oversize"}, state)
            return {
                "validated_input": "{}",
                "input_format": "oversize",
                "enriched_context": enriched,
                "error_code": "INPUT_TOO_LONG",
                "error_message": f"input exceeds {_MAX_INPUT} chars",
                "status": AgentStatus.SUCCESS.value,
            }

        text = normalized
        records = _parse_records(text)
        if records is not None:
            unauthorized = [r.get("record_id", "?") for r in records if r.get("authorized") is False]
            if unauthorized:
                # Access-scope violation — a non-authorized record must never be processed into a packet.
                emit_trace_event(
                    "request_validate.rejected",
                    {"reason": "unauthorized_records", "rejected_count": len(unauthorized)},
                    state,
                )
                return {
                    "validated_input": "{}",
                    "input_format": "unauthorized",
                    "enriched_context": enriched,
                    "error_code": "UNAUTHORIZED_RECORDS",
                    "error_message": "one or more records are not authorized (access scope); " "input not processed",
                    "status": AgentStatus.SUCCESS.value,
                }

        parsed, fmt = self._parse(text)
        emit_trace_event(
            "request_validate.validated", {"input_format": fmt, "record_count": len(parsed["records"])}, state
        )
        return {
            "validated_input": json.dumps(parsed, ensure_ascii=False),
            "input_format": fmt,
            "enriched_context": enriched,
            "status": AgentStatus.SUCCESS.value,
        }

    def _parse(self, text: str) -> tuple[dict[str, Any], str]:
        """Parse a structured disclosure request or a plain NL request.

        Every **supplied metadata / identifier** field (record_id / title / provenance / the request
        dict / policy_hint) is S-1 hygiene-redacted before it persists to ``validated_input`` (design:
        no raw PII / credentials in State beyond the authorized record content under review). Record
        ``content`` — the payload under review — keeps PII (so the deterministic scan can flag it) but
        has control chars + credential tokens stripped; the output packet is PII-redacted at S-3.
        """
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return self._from_dict(obj), "json"
        except (ValueError, TypeError):
            pass
        # NL request with no attached records → 0-record path (out-of-scope safe answer downstream).
        return {"request": {"subject": hygiene_metadata(text)}, "records": [], "policy_hint": None}, "text"

    def _from_dict(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Rebuild {request, records, policy_hint} with every supplied field routed through S-1 hygiene.

        Records are reconstructed field-by-field (whitelist) so no un-hygiened supplied field slips into
        State: identifiers/metadata (record_id / title / provenance) go through full metadata hygiene
        (credential + PII redaction); ``content`` (the payload under review) is credential/control-char
        stripped but keeps PII for candidate flagging. ``record_id`` stays a consistent join key because
        the same hygiened body is read by the inner inventory / policy-flag nodes.
        """
        records: list[dict[str, Any]] = []
        for r in obj.get("records", []):
            if not isinstance(r, dict):
                continue
            record: dict[str, Any] = {
                "record_id": hygiene_metadata(str(r.get("record_id", "") or "")) or "UNKNOWN",
                "title": hygiene_metadata(str(r.get("title", "") or "")),
                "authorized": r.get("authorized"),
                "content": hygiene_content(str(r.get("content", "") or "")),
            }
            if "provenance" in r:
                record["provenance"] = hygiene_metadata(str(r.get("provenance", "") or ""))
            records.append(record)

        request = obj.get("request", {})
        request = hygiene_metadata(request) if isinstance(request, dict) else {}
        policy_hint = obj.get("policy_hint")
        policy_hint = hygiene_metadata(policy_hint) if isinstance(policy_hint, str) else None
        return {"request": request, "records": records, "policy_hint": policy_hint}
